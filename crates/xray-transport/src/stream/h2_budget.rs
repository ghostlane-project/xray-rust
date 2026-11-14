//! HTTP/2 receive credit handed back within the process's byte budget.
//!
//! A stream's receive window is what its peer may send before it is read:
//! h2 queues every DATA frame the window lets in. Handing credit back as a
//! reader takes bytes keeps the full window open for the life of the stream,
//! whether or not the process can hold it. Here the credit a reader frees is
//! handed back only while the stream's exposure, the credit the peer still
//! has plus the bytes received and not read, stays within the flow's floor
//! and the budget's bytes the stream holds ([`WindowGate`]); the rest waits
//! until a later read or until the budget has bytes again.
//!
//! The SETTINGS a handshake sends are unchanged, and so is each WINDOW_UPDATE
//! h2 writes: it still sends one when the credit handed back passes its
//! threshold. Only when that happens moves.

use h2::FlowControl;

use crate::memory_budget::WindowGate;

/// Hands back as much of the credit `gate` owes as the budget allows, and
/// returns how much that was.
pub(crate) fn hand_back(
    gate: &mut WindowGate<'_>,
    flow: &mut FlowControl,
) -> Result<usize, h2::Error> {
    let owed = gate.owed();
    if owed == 0 {
        return Ok(0);
    }
    // h2 counts what a reader took and nobody released as received.
    let unreleased = flow.used_capacity();
    let peer_credit = usize::try_from(flow.available_capacity()).unwrap_or(0);
    let exposure = peer_credit.saturating_add(unreleased).saturating_sub(owed);
    let granted = gate.grant(exposure);
    if granted > 0 {
        flow.release_capacity(granted)?;
    }
    Ok(granted)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use h2::{client, server};
    use http::{Request, Response};

    use super::*;
    use crate::memory_budget::{ByteBudget, ByteBudgetSettings};

    const KIB: usize = 1024;
    const WINDOW: u32 = 256 * 1024;

    /// What the peer has been allowed to send and has not had read.
    fn exposure(flow: &FlowControl, gate: &WindowGate<'_>) -> usize {
        (usize::try_from(flow.available_capacity()).unwrap_or(0) + flow.used_capacity())
            .saturating_sub(gate.owed())
    }

    #[tokio::test]
    async fn a_reader_hands_back_no_more_credit_than_the_budget_holds() {
        let budget: &'static ByteBudget =
            Box::leak(Box::new(ByteBudget::with_settings(ByteBudgetSettings {
                capacity: 64 * KIB,
                floor: 4 * KIB,
            })));
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
            // Sends as fast as the credit lets it, 2 MiB in all.
            let mut left = 2 * 1024 * 1024;
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
        let mut body = response.await.unwrap().into_body();
        let mut gate = WindowGate::new(budget);

        let mut read = 0;
        let mut most_exposed = 0;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            read += chunk.len();
            gate.consumed(chunk.len());
            hand_back(&mut gate, body.flow_control()).unwrap();
            // Past the handshake's credit, the peer never has more out than
            // the floor and the budget's share the stream holds.
            if read > WINDOW as usize {
                most_exposed = most_exposed.max(exposure(body.flow_control(), &gate));
                assert!(gate.held() <= 32 * KIB, "a lone window takes half of B");
            }
        }
        assert_eq!(read, 2 * 1024 * 1024);
        assert!(
            most_exposed <= 4 * KIB + 32 * KIB,
            "exposed {most_exposed} bytes"
        );
        drop(gate);
        assert_eq!(budget.in_use(), 0);
        server.await.unwrap();
    }
}
