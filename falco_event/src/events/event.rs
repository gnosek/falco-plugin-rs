use crate::event_derive::{EventMetadata, PayloadToBytes};
use crate::events::to_bytes::EventToBytes;
use std::io::Write;

#[derive(Debug)]
pub struct Event<T> {
    pub metadata: EventMetadata,
    pub params: T,
}

impl<T: PayloadToBytes> EventToBytes for Event<T> {
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.params.write(&self.metadata, writer)
    }
}
