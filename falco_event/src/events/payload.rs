use crate::events::EventMetadata;
use crate::fields::FromBytesError;
use std::collections::BTreeSet;
use std::io::Write;
use thiserror::Error;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EventDirection {
    Entry,
    Exit,
}

pub trait EventPayload {
    const ID: u16;
    const SOURCE: Option<&'static str>;
}

#[inline]
pub const fn event_direction(event_type_id: u16) -> EventDirection {
    match event_type_id % 2 {
        0 => EventDirection::Entry,
        1 => EventDirection::Exit,
        _ => unreachable!(),
    }
}

pub trait AnyEventPayload {
    const SOURCES: &'static [Option<&'static str>];
    const EVENT_TYPES: &'static [u16];

    /// Get all the event sources for this payload type
    ///
    /// This is intended for internal use only. If all the items in `SOURCES` are `Some()`,
    /// the function returns the inner strings with duplicates removed. If any item is `None`
    /// (indicating a supported event may come from any source), an empty vector is returned
    /// (again, indicating all sources).
    fn event_sources() -> Vec<&'static str> {
        let mut sources = BTreeSet::new();
        for source in Self::SOURCES {
            if let Some(source) = source {
                sources.insert(*source);
            } else {
                return Vec::new();
            }
        }

        sources.into_iter().collect()
    }
}

impl<T: EventPayload> AnyEventPayload for T {
    const SOURCES: &'static [Option<&'static str>] = const {
        match T::SOURCE {
            Some(s) => &[Some(s)],
            None => &[],
        }
    };
    const EVENT_TYPES: &'static [u16] = &[T::ID];
}
#[derive(Debug, Error)]
pub enum PayloadFromBytesError {
    /// Failed to parse a particular field
    #[error("failed to parse field {0}")]
    NamedField(&'static str, #[source] FromBytesError),

    /// Type mismatch
    #[error("type mismatch")]
    TypeMismatch,

    /// Truncated event
    #[error("truncated event (wanted {wanted}, got {got})")]
    TruncatedEvent { wanted: usize, got: usize },

    /// Unsupported event type
    #[error("unsupported event type {0}")]
    UnsupportedEventType(u16),
}

pub trait PayloadToBytes {
    fn binary_size(&self) -> usize;

    fn write<W: Write>(&self, metadata: &EventMetadata, writer: W) -> std::io::Result<()>;
}
