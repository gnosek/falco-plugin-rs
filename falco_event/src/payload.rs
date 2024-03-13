use std::io::Write;

use crate::events::EventType;
use crate::from_bytes::FromBytesResult;
use crate::EventMetadata;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EventDirection {
    Entry,
    Exit,
}

pub trait EventPayload {
    const ID: EventType;
    const LARGE: bool;
    const NAME: &'static str;

    fn direction() -> EventDirection {
        match Self::ID as u32 % 2 {
            0 => EventDirection::Entry,
            1 => EventDirection::Exit,
            _ => unreachable!(),
        }
    }
}

pub trait PayloadToBytes {
    fn write<W: Write>(&self, metadata: &EventMetadata, writer: W) -> std::io::Result<()>;
}

pub trait PayloadFromBytes<'a>: Sized {
    fn read(params: impl Iterator<Item = FromBytesResult<&'a [u8]>>) -> FromBytesResult<Self>;
}
