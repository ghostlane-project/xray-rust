//! The UDP lane: one `udpwire` frame per record, sealed under
//! `olcrtc/udp/v1` (`client/udp.go:310-360`, `tunnelcore/core.go:23-26`).
//!
//! The lane shares the run's key set, and so its replay window, with the
//! data and control lanes, under a counter and prefix of its own. A sealed
//! frame is at most [`olc_wire::sizes::UDP_MAX_RECORD`] bytes (1515), which
//! is the one buffer a [`DatagramLane`] keeps.

use std::sync::Arc;

use olc_wire::record::{KeySet, Lane, OpenError, SealError, RECORD_HEADER_SIZE, TAG_SIZE};
use olc_wire::sizes::UDP_MAX_RECORD;
use olc_wire::udpwire::{self, FrameType};

/// Why a datagram was not sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealDatagramError {
    /// The frame is not one Go would encode.
    #[error("encode udp frame: {0}")]
    Encode(#[from] udpwire::Error),
    /// The lane has no counter left.
    #[error("seal udp frame: {0}")]
    Seal(#[from] SealError),
}

/// Why a datagram record was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenDatagramError {
    /// The record did not open.
    #[error("open udp frame: {0}")]
    Open(#[from] OpenError),
    /// It opened, but is not a frame Go would decode.
    #[error("decode udp frame: {0}")]
    Decode(#[from] udpwire::Error),
}

/// Seals and opens the UDP lane's records.
#[derive(Debug)]
pub struct DatagramLane {
    keys: Arc<KeySet>,
    record: Vec<u8>,
}

impl DatagramLane {
    /// The lane over the run's key set.
    #[must_use]
    pub fn new(keys: Arc<KeySet>) -> Self {
        Self {
            keys,
            record: Vec::with_capacity(UDP_MAX_RECORD),
        }
    }

    /// Encodes the frame as Go's `udpwire.Encode` does (see
    /// [`udpwire::encode`]), seals it, and returns the record.
    ///
    /// # Errors
    /// [`SealDatagramError`]; nothing is sealed then.
    pub fn seal(
        &mut self,
        kind: FrameType,
        flow_id: u64,
        host: &[u8],
        port: u16,
        payload: &[u8],
    ) -> Result<&[u8], SealDatagramError> {
        self.record.clear();
        self.record.resize(RECORD_HEADER_SIZE, 0);
        udpwire::encode(kind, flow_id, host, port, payload, &mut self.record)?;
        self.record.resize(self.record.len() + TAG_SIZE, 0);
        self.keys.seal_in_place(Lane::Udp, &mut self.record)?;
        Ok(&self.record)
    }

    /// Opens a record in place and decodes its frame, which borrows it.
    ///
    /// # Errors
    /// [`OpenDatagramError`].
    pub fn open<'r>(&self, record: &'r mut [u8]) -> Result<udpwire::Frame<'r>, OpenDatagramError> {
        let wire = self.keys.open_in_place(Lane::Udp, record)?;
        Ok(udpwire::decode(wire)?)
    }
}

#[cfg(test)]
mod tests {
    use olc_wire::record::Role;

    use super::*;

    #[test]
    fn a_datagram_crosses_and_the_buffer_holds_the_largest() {
        let client = Arc::new(KeySet::new(&[3; 32], Role::Client).unwrap());
        let server = Arc::new(KeySet::new(&[3; 32], Role::Server).unwrap());
        let mut tx = DatagramLane::new(client);
        let rx = DatagramLane::new(server);
        let cap = tx.record.capacity();
        let host = [b'a'; 255];
        let mut record = tx
            .seal(FrameType::Packet, 1, &host, 53, &[7; 1200])
            .unwrap()
            .to_vec();
        assert_eq!(record.len(), UDP_MAX_RECORD);
        assert_eq!(
            tx.record.capacity(),
            cap,
            "the largest frame fits the buffer"
        );
        let frame = rx.open(&mut record).unwrap();
        assert_eq!(frame.payload, &[7; 1200]);
        assert_eq!(frame.port, 53);
    }
}
