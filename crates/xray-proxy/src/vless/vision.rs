use bytes::BytesMut;
use rand::Rng;
use thiserror::Error;

const HEADER_LEN: usize = 5;
const USER_ID_LEN: usize = 16;
const MAX_CONTENT_LEN: usize = u16::MAX as usize;
pub const DEFAULT_VISION_SEED: [u32; 4] = [900, 500, 900, 256];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionCommand {
    Continue = 0,
    End = 1,
    Direct = 2,
}

impl TryFrom<u8> for VisionCommand {
    type Error = VisionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Continue),
            1 => Ok(Self::End),
            2 => Ok(Self::Direct),
            command => Err(VisionError::UnknownCommand(command)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpaddedVisionBlock {
    pub command: VisionCommand,
    pub payload: BytesMut,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VisionError {
    #[error("vision block is shorter than header")]
    ShortBlock,
    #[error("vision user id mismatch")]
    UserMismatch,
    #[error("unknown vision command {0}")]
    UnknownCommand(u8),
    #[error("vision block length is inconsistent")]
    LengthMismatch,
    #[error("vision payload length {len} exceeds u16 content length limit")]
    PayloadTooLarge { len: usize },
}

/// The longest head a frame has: the user ID the first frame names, then
/// the command and the payload's and the padding's lengths.
pub(crate) const FRAME_HEAD_MAX: usize = USER_ID_LEN + HEADER_LEN;

/// A padded frame's head and the length of the padding after its payload.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameHead {
    bytes: [u8; FRAME_HEAD_MAX],
    len: u8,
    /// Zeros after the payload, at most `u16::MAX`.
    pub(crate) padding_len: u16,
}

impl FrameHead {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

pub struct VisionPadding {
    user_id: [u8; USER_ID_LEN],
    /// Keeps the full planned seed shape; this deterministic slice currently uses indices 0 and 2.
    seed: [u32; 4],
    user_id_emitted: bool,
}

impl VisionPadding {
    pub fn new(user_id: [u8; USER_ID_LEN], seed: [u32; 4]) -> Self {
        Self {
            user_id,
            seed,
            user_id_emitted: false,
        }
    }

    pub fn pad(
        &mut self,
        payload: BytesMut,
        command: VisionCommand,
        deterministic_extra_padding: u16,
    ) -> Result<BytesMut, VisionError> {
        let mut padded = BytesMut::new();
        self.pad_into(&payload, command, deterministic_extra_padding, &mut padded)?;
        Ok(padded)
    }

    /// Appends one padded frame directly to `output`, avoiding the per-write
    /// temporary buffers `pad` needs on the hot relay path.
    pub fn pad_into(
        &mut self,
        payload: &[u8],
        command: VisionCommand,
        deterministic_extra_padding: u16,
        output: &mut BytesMut,
    ) -> Result<(), VisionError> {
        self.pad_into_with_long_padding(payload, command, true, deterministic_extra_padding, output)
    }

    pub fn pad_into_with_long_padding(
        &mut self,
        payload: &[u8],
        command: VisionCommand,
        long_padding: bool,
        deterministic_extra_padding: u16,
        output: &mut BytesMut,
    ) -> Result<(), VisionError> {
        let head = self.frame_head(
            payload.len(),
            command,
            long_padding,
            deterministic_extra_padding,
        )?;
        output.reserve(head.bytes().len() + payload.len() + usize::from(head.padding_len));
        output.extend_from_slice(head.bytes());
        output.extend_from_slice(payload);
        output.resize(output.len() + usize::from(head.padding_len), 0);

        Ok(())
    }

    /// What a padded frame of `content_len` payload bytes carries around
    /// them: its head and how many zeros follow. The same draw, and the
    /// same bytes, as [`Self::pad_into_with_long_padding`] writes before and
    /// after the payload, which a writer may then send from where it is.
    pub(crate) fn frame_head(
        &mut self,
        content_len: usize,
        command: VisionCommand,
        long_padding: bool,
        deterministic_extra_padding: u16,
    ) -> Result<FrameHead, VisionError> {
        if content_len > MAX_CONTENT_LEN {
            return Err(VisionError::PayloadTooLarge { len: content_len });
        }

        let padding_len = self.padding_len(content_len, long_padding, deterministic_extra_padding);
        let mut head = FrameHead {
            bytes: [0; FRAME_HEAD_MAX],
            len: 0,
            padding_len: padding_len as u16,
        };
        let mut at = 0;
        if !self.user_id_emitted {
            head.bytes[..USER_ID_LEN].copy_from_slice(&self.user_id);
            at = USER_ID_LEN;
            self.user_id_emitted = true;
        }
        head.bytes[at] = command as u8;
        head.bytes[at + 1..at + 3].copy_from_slice(&(content_len as u16).to_be_bytes());
        head.bytes[at + 3..at + 5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        head.len = (at + HEADER_LEN) as u8;
        Ok(head)
    }

    fn padding_len(
        &self,
        content_len: usize,
        long_padding: bool,
        deterministic_extra_padding: u16,
    ) -> usize {
        if deterministic_extra_padding != 0 {
            return deterministic_extra_padding as usize;
        }

        if long_padding && content_len < self.seed[0] as usize {
            let padding_len = (self.seed[2] as usize)
                .saturating_sub(content_len)
                .saturating_add(random_padding_len(self.seed[1]));
            padding_len.min(MAX_CONTENT_LEN)
        } else {
            random_padding_len(self.seed[3]).min(MAX_CONTENT_LEN)
        }
    }
}

fn random_padding_len(upper_bound: u32) -> usize {
    if upper_bound == 0 {
        return 0;
    }

    #[cfg(test)]
    if let Some(len) = seeded::draw(upper_bound) {
        return len;
    }

    rand::thread_rng().gen_range(0..upper_bound) as usize
}

/// Padding lengths a test can repeat: drawn on its thread from a generator
/// it seeds, the same draws as from the thread's generator otherwise.
#[cfg(test)]
pub(crate) mod seeded {
    use std::cell::RefCell;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    thread_local! {
        static RNG: RefCell<Option<StdRng>> = const { RefCell::new(None) };
    }

    /// While the guard lives, this thread draws padding from `seed`.
    pub(crate) fn seed(seed: u64) -> Guard {
        RNG.with(|rng| *rng.borrow_mut() = Some(StdRng::seed_from_u64(seed)));
        Guard
    }

    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            RNG.with(|rng| *rng.borrow_mut() = None);
        }
    }

    pub(super) fn draw(upper_bound: u32) -> Option<usize> {
        RNG.with(|rng| {
            rng.borrow_mut()
                .as_mut()
                .map(|rng| rng.gen_range(0..upper_bound) as usize)
        })
    }
}

pub fn unpad_vision_block(
    padded: &[u8],
    expected_user_id: &[u8; USER_ID_LEN],
) -> Result<UnpaddedVisionBlock, VisionError> {
    if padded.len() < HEADER_LEN {
        return Err(VisionError::ShortBlock);
    }

    let offset = match padded.get(..USER_ID_LEN) {
        Some(user_id) if user_id == expected_user_id => USER_ID_LEN,
        _ => match parse_header(padded, 0) {
            Ok(header) if header.total_len == padded.len() => 0,
            Err(VisionError::UnknownCommand(command)) => {
                return Err(VisionError::UnknownCommand(command));
            }
            _ if padded.len() >= USER_ID_LEN + HEADER_LEN => {
                return Err(VisionError::UserMismatch);
            }
            Ok(_) => return Err(VisionError::LengthMismatch),
            Err(err) => return Err(err),
        },
    };

    let header = match parse_header(padded, offset) {
        Ok(header) if header.total_len == padded.len() - offset => header,
        Ok(_) => return Err(VisionError::LengthMismatch),
        Err(err) => return Err(err),
    };

    let payload_start = offset + HEADER_LEN;
    let payload_end = payload_start + header.content_len;
    Ok(UnpaddedVisionBlock {
        command: header.command,
        payload: BytesMut::from(&padded[payload_start..payload_end]),
    })
}

#[derive(Debug, Clone, Copy)]
struct VisionHeader {
    command: VisionCommand,
    content_len: usize,
    total_len: usize,
}

fn parse_header(padded: &[u8], offset: usize) -> Result<VisionHeader, VisionError> {
    if padded.len() < offset + HEADER_LEN {
        return Err(VisionError::ShortBlock);
    }

    let command = VisionCommand::try_from(padded[offset])?;
    let content_len = u16::from_be_bytes([padded[offset + 1], padded[offset + 2]]) as usize;
    let padding_len = u16::from_be_bytes([padded[offset + 3], padded[offset + 4]]) as usize;
    let total_len = HEADER_LEN + content_len + padding_len;

    Ok(VisionHeader {
        command,
        content_len,
        total_len,
    })
}
