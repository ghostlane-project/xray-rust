use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RemoteReadEnd {
    Closed,
    Failed,
}

/// Coalesce only immediately available data. H2/TLS readers can return one
/// small frame per poll even when more frames are ready; handing each frame
/// to the stack separately adds avoidable task/channel round trips. Preserve
/// a terminal result following data so the bridge delivers those bytes first.
///
/// The bytes go into a buffer the relays' pool lends for this read, which
/// the process's byte budget pays for beyond the flow's floor
/// ([`RelayBuffer`]): a read that finds nothing gives it back at once, so a
/// quiet flow holds none. The read's bytes are `buffer.filled(len)` until
/// the caller marks them written.
pub(super) async fn read_remote_batch<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut RelayBuffer<'_>,
) -> (usize, Option<RemoteReadEnd>) {
    let mut end = None;
    let mut source = Coalescing {
        reader,
        end: &mut end,
    };
    let read =
        std::future::poll_fn(|cx| buffer.poll_read(cx, std::pin::Pin::new(&mut source))).await;
    match read {
        Ok(0) => (0, Some(end.unwrap_or(RemoteReadEnd::Closed))),
        Ok(read) => (read, end),
        Err(_) => (0, Some(RemoteReadEnd::Failed)),
    }
}

/// A reader that fills what it is given with every read its source has
/// ready, and keeps an end that came after data for its caller.
struct Coalescing<'a, R> {
    reader: &'a mut R,
    end: &'a mut Option<RemoteReadEnd>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Coalescing<'_, R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();
        let start = buffer.filled().len();
        while buffer.remaining() > 0 {
            let before = buffer.filled().len();
            match std::pin::Pin::new(&mut *this.reader).poll_read(cx, buffer) {
                Poll::Pending if before == start => return Poll::Pending,
                Poll::Pending => break,
                Poll::Ready(Err(error)) if before == start => return Poll::Ready(Err(error)),
                Poll::Ready(Err(_)) => {
                    *this.end = Some(RemoteReadEnd::Failed);
                    break;
                }
                Poll::Ready(Ok(())) if buffer.filled().len() == before => {
                    if before != start {
                        *this.end = Some(RemoteReadEnd::Closed);
                    }
                    break;
                }
                Poll::Ready(Ok(())) => {}
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
pub(super) struct DownloadDelivery {
    accepted: tokio::sync::oneshot::Sender<()>,
    // Cancellation of the sending future must not unlock another DNS writer
    // while its previous chunk is still in the event or pending-data queue.
    _serial: Arc<tokio::sync::OwnedMutexGuard<()>>,
}

impl DownloadDelivery {
    pub(super) fn complete(self) {
        let _ = self.accepted.send(());
    }

    #[cfg(test)]
    pub(super) fn test() -> Self {
        Self {
            accepted: tokio::sync::oneshot::channel().0,
            _serial: Arc::new(
                Arc::new(tokio::sync::Mutex::new(()))
                    .try_lock_owned()
                    .unwrap(),
            ),
        }
    }
}

/// Serializes complete writes (including DNS frames) within one TCP flow.
/// An acknowledgement permits another chunk only when the stack has room in
/// its bounded prefetch queue. There is at most one unacknowledged 64 KiB chunk
/// per flow, including deferred data; admitted chunks cannot fill the previous
/// multi-megabyte queues or stop the shared control/UDP channel.
pub(super) async fn send_remote_data(
    stack_tx: &mpsc::Sender<StackEvent>,
    serial: &Arc<tokio::sync::Mutex<()>>,
    handle: SocketHandle,
    generation: u64,
    mut data: Bytes,
) -> Result<(), ()> {
    let serial = Arc::new(serial.clone().lock_owned().await);
    let split_frame = data.len() > TCP_DOWNLOAD_CHUNK_SIZE;
    while !data.is_empty() {
        let chunk = if !split_frame {
            std::mem::take(&mut data)
        } else {
            // Do not retain an entire DNS response in a small queued slice.
            let take = data.len().min(TCP_DOWNLOAD_CHUNK_SIZE);
            let chunk = Bytes::copy_from_slice(&data[..take]);
            data = data.slice(take..);
            chunk
        };
        let (accepted, delivered) = tokio::sync::oneshot::channel();
        stack_tx
            .send(StackEvent::RemoteData {
                handle,
                generation,
                data: chunk,
                delivery: DownloadDelivery {
                    accepted,
                    _serial: serial.clone(),
                },
            })
            .await
            .map_err(|_| ())?;
        delivered.await.map_err(|_| ())?;
    }
    Ok(())
}

pub(super) type PendingDownload<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Option<Result<(), ()>>> + Send + 'a>>;
