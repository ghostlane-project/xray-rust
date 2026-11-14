use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use quinn::{RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, TryAcquireError};
use tokio::time::timeout;
use xray_proxy::hysteria::{
    decode_tcp_response, encode_tcp_request, TcpRequest, WireError, MAX_MESSAGE_LENGTH,
    MAX_PADDING_LENGTH,
};
use xray_routing::{Network, Target};

use super::client::{random_padding, Shared};
use super::{HysteriaClient, HysteriaError};
use crate::stream::QUIC_SEND_WINDOW_SAMPLE_BYTES;
use crate::TransportStream;

const RESPONSE_HEADER_LIMIT: usize = 1 + 8 + MAX_MESSAGE_LENGTH + 8 + MAX_PADDING_LENGTH;
/// Bytes a stream reads between refits of its connection's windows to the
/// byte budget ([`Shared::fit_windows`]): 256 KiB, a twelfth of a
/// constrained connection's 3 MiB, so a share follows the other windows of
/// the process within a fraction of the window.
pub(super) const BUDGET_SAMPLE_BYTES: usize = 256 * 1024;

struct PendingStream {
    streams: Option<(SendStream, RecvStream)>,
}
impl Drop for PendingStream {
    fn drop(&mut self) {
        if let Some((send, recv)) = &mut self.streams {
            let _ = send.reset(VarInt::from_u32(0));
            let _ = recv.stop(VarInt::from_u32(0));
        }
    }
}

pub struct HysteriaTcpStream {
    send: SendStream,
    recv: RecvStream,
    prefix: Bytes,
    send_finished: bool,
    bytes_since_window_sample: usize,
    bytes_since_budget_sample: usize,
    connection: Arc<Shared>,
    /// Given back first when the stream is dropped, so that the windows are
    /// fitted to the streams still open.
    slot: Option<OwnedSemaphorePermit>,
}

impl HysteriaClient {
    pub async fn open_tcp(&self, target: &Target) -> Result<HysteriaTcpStream, HysteriaError> {
        let address = super::address(target, Network::Tcp)?;
        if !self.is_live() {
            return Err(HysteriaError::Closed);
        }
        let slot = Arc::clone(&self.shared.tcp_slots)
            .try_acquire_owned()
            .map_err(|error| match error {
                TryAcquireError::Closed => HysteriaError::Closed,
                TryAcquireError::NoPermits => HysteriaError::SessionLimit,
            })?;
        // The response comes through the windows the open stream is due.
        self.shared.fit_windows();
        let opened = timeout(self.shared.limits.operation_timeout, async {
            let streams = self
                .shared
                .connection()?
                .open_bi()
                .await
                .map_err(|_| HysteriaError::Stream)?;
            let mut pending = PendingStream {
                streams: Some(streams),
            };
            let (send, recv) = pending.streams.as_mut().expect("opened stream");
            let padding = random_padding(64, 512);
            let request = encode_tcp_request(&TcpRequest {
                address: &address,
                padding: padding.as_bytes(),
            })
            .map_err(|_| HysteriaError::Target)?;
            send.write_all(&request)
                .await
                .map_err(|_| HysteriaError::Stream)?;
            let mut received = Vec::new();
            let consumed = loop {
                match decode_tcp_response(&received) {
                    Ok((response, consumed)) => {
                        if response.status != 0 {
                            return Err(HysteriaError::TcpRejected);
                        }
                        break consumed;
                    }
                    Err(WireError::Incomplete) => {}
                    Err(_) => return Err(HysteriaError::TcpResponse),
                }
                if received.len() >= RESPONSE_HEADER_LIMIT {
                    return Err(HysteriaError::TcpResponse);
                }
                let mut chunk = [0u8; 1024];
                let count = AsyncReadExt::read(recv, &mut chunk)
                    .await
                    .map_err(|_| HysteriaError::Stream)?;
                if count == 0 {
                    return Err(HysteriaError::TcpResponse);
                }
                received.extend_from_slice(&chunk[..count]);
            };
            let prefix = Bytes::copy_from_slice(&received[consumed..]);
            let (send, recv) = pending.streams.take().expect("opened stream");
            Ok(HysteriaTcpStream {
                send,
                recv,
                prefix,
                send_finished: false,
                bytes_since_window_sample: 0,
                bytes_since_budget_sample: 0,
                connection: Arc::clone(&self.shared),
                slot: Some(slot),
            })
        })
        .await
        .map_err(|_| HysteriaError::Timeout)
        .and_then(|opened| opened);
        if opened.is_err() {
            // The slot went with the attempt.
            self.shared.fit_windows();
        }
        opened
    }
}

impl AsyncRead for HysteriaTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let count = output.remaining().min(this.prefix.len());
            output.put_slice(&this.prefix[..count]);
            this.prefix.advance(count);
            if this.prefix.is_empty() {
                this.prefix = Bytes::new();
            }
            return Poll::Ready(Ok(()));
        }
        let before = output.filled().len();
        let result = redact_io(AsyncRead::poll_read(Pin::new(&mut this.recv), cx, output));
        if let Poll::Ready(Ok(())) = result {
            this.bytes_since_budget_sample += output.filled().len() - before;
            if this.bytes_since_budget_sample >= BUDGET_SAMPLE_BYTES {
                this.bytes_since_budget_sample = 0;
                this.connection.fit_windows();
            }
        }
        result
    }
}

impl AsyncWrite for HysteriaTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = redact_io(AsyncWrite::poll_write(Pin::new(&mut this.send), cx, input));
        if let Poll::Ready(Ok(written)) = result {
            this.bytes_since_window_sample += written;
            if this.bytes_since_window_sample >= QUIC_SEND_WINDOW_SAMPLE_BYTES {
                this.bytes_since_window_sample = 0;
                this.connection.grow_send_window();
                this.connection.fit_windows();
            }
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        redact_io(AsyncWrite::poll_flush(
            Pin::new(&mut self.get_mut().send),
            cx,
        ))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = redact_io(AsyncWrite::poll_shutdown(Pin::new(&mut this.send), cx));
        if matches!(result, Poll::Ready(Ok(()))) {
            this.send_finished = true;
        }
        result
    }
}

impl TransportStream for HysteriaTcpStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

impl Drop for HysteriaTcpStream {
    fn drop(&mut self) {
        if !self.send_finished {
            let _ = self.send.reset(VarInt::from_u32(0));
        }
        let _ = self.recv.stop(VarInt::from_u32(0));
        self.slot.take();
        self.connection.fit_windows();
    }
}

fn redact_io<T>(result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
    match result {
        Poll::Ready(Err(error)) => {
            Poll::Ready(Err(io::Error::new(error.kind(), "Hysteria stream failed")))
        }
        other => other,
    }
}
