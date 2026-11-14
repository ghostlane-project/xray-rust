//! HTTP/2 receive credit handed back within a byte budget.
//!
//! A stream's receive window is what its peer may send before it is read:
//! h2 queues every DATA frame the window lets in. What waits in that queue,
//! and in a transport's own queue after it, is the memory the stream holds;
//! credit the peer has not used holds none. A [`ReceiveGate`] takes bytes of
//! the budget for the queue beyond the flow's floor and, as a reader takes
//! bytes, hands their credit back at once unless the budget is spent and the
//! queue still holds more than the floor. Then the credit waits until the
//! reader has taken the queue down, or until bytes come back to the budget
//! while the reader is away: a gate that holds credit back is listed with
//! its budget, whose settler settles it again ([`SharedGate`]). No task waits
//! on the budget. While the budget is spent, credit a paused reader took
//! still counts in the connection's window, which h2 releases together with
//! the stream's, so the connection's other streams can wait on it, up to the
//! stream's window.
//!
//! The queue is counted as h2 counts it, in payload bytes: received and not
//! released. That is its memory once each frame is read into an allocation of
//! its own; with upstream h2's reader a queued frame is a slice of the
//! connection's read buffer and can hold more.
//!
//! The SETTINGS a handshake sends are unchanged, and so is each WINDOW_UPDATE
//! h2 writes: it still sends one when the credit handed back passes its
//! threshold. Only when that happens moves, and only for a pressed process.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use h2::FlowControl;

use crate::memory_budget::{ByteBudget, ReceiveGate, WithheldCredit};

/// Settles `gate` against what the stream holds now and hands back the
/// credit it grants; returns how much that was.
fn hand_back(
    gate: &mut ReceiveGate<'_>,
    flow: &mut FlowControl,
) -> Result<usize, h2::Error> {
    // h2 counts as used what was received and not released: the queue, and
    // what readers took and the gate still owes.
    let queued = flow.used_capacity().saturating_sub(gate.owed());
    let granted = gate.grant(queued);
    if granted > 0 {
        flow.release_capacity(granted)?;
    }
    Ok(granted)
}

/// One stream's receive gate and its flow control, shared by the stream's
/// reader and its budget's settler.
///
/// The reader settles it at every read and every `Pending`. A read that
/// leaves credit held back lists it with the budget, whose settler settles
/// it again whenever bytes come back while `B` has room, until it holds
/// nothing back: credit a reader took goes back once the budget can hold the
/// queue, whether or not that reader reads again.
pub(crate) struct SharedGate {
    state: Mutex<GateState>,
}

struct GateState {
    gate: ReceiveGate<'static>,
    /// The stream's flow control, until the gate is closed.
    flow: Option<FlowControl>,
    /// In its budget's list of gates that hold credit back.
    listed: bool,
}

impl SharedGate {
    /// A gate on `budget`, for a stream whose flow control is `flow`, or
    /// given later ([`Self::open`]).
    pub(crate) fn new(budget: &'static ByteBudget, flow: Option<FlowControl>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState {
                gate: ReceiveGate::new(budget),
                flow,
                listed: false,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The stream's flow control, once the stream is there to read.
    pub(crate) fn open(&self, flow: FlowControl) {
        self.lock().flow = Some(flow);
    }

    /// A reader took `consumed` bytes, or found nothing queued (0): settles
    /// the gate and hands back the credit it grants; returns how much that
    /// was. Lists the gate with its budget if it holds credit back.
    pub(crate) fn hand_back(self: &Arc<Self>, consumed: usize) -> Result<usize, h2::Error> {
        let mut state = self.lock();
        let GateState { gate, flow, listed } = &mut *state;
        gate.consumed(consumed);
        let Some(flow) = flow.as_mut() else {
            return Ok(0);
        };
        let granted = hand_back(gate, flow)?;
        let list = gate.owed() > 0 && !*listed;
        *listed |= list;
        let budget = gate.budget();
        drop(state);
        if list {
            let gate: Weak<Self> = Arc::downgrade(self);
            budget.list_withheld(gate as Weak<dyn WithheldCredit>);
        }
        Ok(granted)
    }

    /// Ends the stream's part in the budget. Credit its reader took that the
    /// budget held back goes to the connection now, rather than when h2 lets
    /// the stream go; then the queue's bytes of the budget come back, and the
    /// flow control is let go.
    pub(crate) fn close(&self) {
        let mut state = self.lock();
        let GateState { gate, flow, .. } = &mut *state;
        let owed = gate.owed();
        if let Some(flow) = flow.as_mut().filter(|_| owed > 0) {
            // h2 still counts the owed bytes as received and not released,
            // so it takes them back, and for a stream it has reset it sends
            // no stream WINDOW_UPDATE. An error leaves nothing to return: the
            // connection is gone.
            let _ = flow.release_capacity(owed);
        }
        gate.close();
        *flow = None;
    }
}

impl WithheldCredit for SharedGate {
    fn settle(&self) {
        let mut state = self.lock();
        let GateState { gate, flow, .. } = &mut *state;
        if let Some(flow) = flow.as_mut() {
            // An error is the stream's: its reader meets it at its next read.
            let _ = hand_back(gate, flow);
        }
    }

    fn still_withheld(&self) -> bool {
        let mut state = self.lock();
        let withheld = state.flow.is_some() && state.gate.owed() > 0;
        // Cleared under the gate's lock, so a read that holds credit back
        // after this lists the gate again.
        state.listed = withheld;
        withheld
    }
}

impl fmt::Debug for SharedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        formatter
            .debug_struct("SharedGate")
            .field("held", &state.gate.held())
            .field("owed", &state.gate.owed())
            .field("open", &state.flow.is_some())
            .field("listed", &state.listed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use h2::{client, server};
    use http::{Request, Response};

    use super::*;
    use crate::memory_budget::{BudgetPermits, ByteBudget, ByteBudgetSettings};

    const KIB: usize = 1024;
    const WINDOW: u32 = 256 * 1024;

    /// A server that sends `total` bytes on one response as fast as its
    /// credit lets it; and the client's body.
    async fn download(total: usize) -> (h2::RecvStream, tokio::task::JoinHandle<()>) {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = server::Builder::new()
                .initial_connection_window_size(16 * 1024 * 1024)
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
            tokio::spawn(async move { while connection.accept().await.is_some() {} });
            let mut send = respond.send_response(Response::new(()), false).unwrap();
            let mut left = total;
            while left > 0 {
                send.reserve_capacity(left.min(64 * KIB));
                let granted = std::future::poll_fn(|cx| send.poll_capacity(cx))
                    .await
                    .unwrap()
                    .unwrap();
                send.send_data(Bytes::from(vec![1; granted]), false)
                    .unwrap();
                left -= granted;
            }
            send.send_data(Bytes::new(), true).unwrap();
        });
        let (sender, connection) = client::Builder::new()
            .initial_window_size(WINDOW)
            .initial_connection_window_size(16 * 1024 * 1024)
            .handshake::<_, Bytes>(client_io)
            .await
            .unwrap();
        tokio::spawn(connection);
        let mut sender = sender.ready().await.unwrap();
        let request = Request::builder()
            .uri("https://h2-budget.test/")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        (response.await.unwrap().into_body(), server)
    }

    #[tokio::test]
    async fn a_reader_within_the_budget_hands_every_read_back_at_once_and_ends_holding_nothing() {
        // B covers the whole window: no read's credit ever waits, whatever
        // the queue.
        let budget: &'static ByteBudget =
            Box::leak(Box::new(ByteBudget::with_settings(ByteBudgetSettings {
                capacity: 4 * WINDOW as usize,
                floor: 4 * KIB,
            })));
        let (mut body, server) = download(2 * 1024 * 1024).await;
        let mut gate = ReceiveGate::new(budget);
        let mut read = 0;
        let mut most_held = 0;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            read += chunk.len();
            gate.consumed(chunk.len());
            let granted = hand_back(&mut gate, body.flow_control()).unwrap();
            assert_eq!(granted, chunk.len(), "the read's credit went back");
            assert_eq!(gate.owed(), 0);
            most_held = most_held.max(gate.held());
        }
        assert_eq!(read, 2 * 1024 * 1024, "through a 256 KiB window");
        assert!(most_held > 0, "the queue never passed the floor");
        hand_back(&mut gate, body.flow_control()).unwrap();
        assert_eq!(gate.owed(), 0);
        assert_eq!(
            budget.in_use(),
            0,
            "a stream with nothing queued holds nothing"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_pressed_stream_gets_credit_back_only_with_its_queue_within_the_floor_and_finishes() {
        // Another holder has all of B: the stream's credit goes back only
        // when its reader has taken the queue down to the floor, and the
        // stream still finishes.
        const FLOOR: usize = 4 * KIB;
        let budget: &'static ByteBudget =
            Box::leak(Box::new(ByteBudget::with_settings(ByteBudgetSettings {
                capacity: 64 * KIB,
                floor: FLOOR,
            })));
        let mut other = BudgetPermits::new(budget);
        other.try_hold(64 * KIB);
        let (mut body, server) = download(1024 * 1024).await;
        let mut gate = ReceiveGate::new(budget);
        let mut read = 0;
        let mut held_back = 0;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            read += chunk.len();
            gate.consumed(chunk.len());
            let queued = body.flow_control().used_capacity() - gate.owed();
            let granted = hand_back(&mut gate, body.flow_control()).unwrap();
            if queued > FLOOR {
                assert_eq!(granted, 0, "{queued} B queued, beyond the floor");
                held_back += 1;
            } else {
                assert!(granted >= chunk.len(), "within the floor it never waits");
                assert_eq!(gate.owed(), 0);
            }
            assert_eq!(gate.held(), 0, "B has nothing for it");
        }
        assert_eq!(read, 1024 * 1024);
        assert!(held_back > 0, "the queue never passed the floor");
        drop(other);
        server.await.unwrap();
    }
}
