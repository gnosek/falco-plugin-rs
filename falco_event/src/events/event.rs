use crate::events::to_bytes::EventToBytes;
use crate::events::{AnyEventPayload, EventMetadata, PayloadToBytes};
use crate::events::{FromRawEvent, PayloadFromBytesError, RawEvent};
use std::fmt::{Debug, Formatter};
use std::io::Write;

/// A Falco event.
///
/// This struct represents a Falco event with metadata and parameters. The [`EventMetadata`] contains
/// fields common to all events (the timestamp and thread ID), while the `params` field contains
/// the event-specific data.
#[derive(Clone)]
pub struct Event<T> {
    /// The metadata for the event, which includes common fields like timestamp and thread ID.
    pub metadata: EventMetadata,

    /// The parameters for the event, which are specific to the type of event.
    pub params: T,
}

impl<T: Debug> Debug for Event<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {:?}", self.metadata, self.params)
    }
}

impl<T: PayloadToBytes> EventToBytes for Event<T> {
    #[inline]
    fn binary_size(&self) -> usize {
        26 + self.params.binary_size()
    }

    #[inline]
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.params.write(&self.metadata, writer)
    }
}

impl<'a, 'b, T: FromRawEvent<'a>> TryFrom<&'b RawEvent<'a>> for Event<T> {
    type Error = PayloadFromBytesError;

    #[inline]
    fn try_from(raw: &'b RawEvent<'a>) -> Result<Self, Self::Error> {
        raw.load::<T>()
    }
}

impl<T: AnyEventPayload> AnyEventPayload for Event<T> {
    const SOURCES: &'static [Option<&'static str>] = T::SOURCES;
    const EVENT_TYPES: &'static [u16] = T::EVENT_TYPES;
}
