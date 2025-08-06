use crate::events::EventMetadata;
use crate::fields::FromBytesError;
use std::collections::BTreeSet;
use std::io::Write;
use thiserror::Error;

/// Represents the direction of an event, either an entry or an exit.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[allow(missing_docs)]
pub enum EventDirection {
    Entry,
    Exit,
}

/// A trait to identify event payloads in the plugin framework.
///
/// Each event has two main identifiers:
/// - `ID`: a unique identifier for the event type, which is a 16-bit unsigned integer.
/// - `SOURCE`: the name of the event source. For plugin events, this is the name of the plugin
///   that generated the event. For syscall events, this is always `Some("syscall")`.
///
/// The source can be `None` if the event can come from multiple sources, such as in the case of
/// async or plugin events coming from different plugins.
#[allow(missing_docs)]
pub trait EventPayload {
    const ID: u16;
    const SOURCE: Option<&'static str>;
}

/// Get the event direction from the event type ID.
#[inline]
pub const fn event_direction(event_type_id: u16) -> EventDirection {
    match event_type_id % 2 {
        0 => EventDirection::Entry,
        1 => EventDirection::Exit,
        _ => unreachable!(),
    }
}

/// A trait to identify a group of event payloads, each having a unique identifier and source.
pub trait AnyEventPayload {
    /// The sources of the events that this payload type can represent.
    const SOURCES: &'static [Option<&'static str>];

    /// The event types that this payload type can represent.
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

/// Error type for parsing event payloads from bytes
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
    TruncatedEvent {
        /// expected length
        wanted: usize,
        /// actual length
        got: usize,
    },

    /// Unsupported event type
    #[error("unsupported event type {0}")]
    UnsupportedEventType(u16),
}

/// Trait for converting event payloads to bytes
pub trait PayloadToBytes {
    /// Get the binary size of the payload
    ///
    /// This is the size of the payload in bytes, excluding the event header. This can (and should)
    /// be used to preallocate buffers for writing the payload.
    fn binary_size(&self) -> usize;

    /// Write the payload to a writer implementing `[std::io::Write]`.
    fn write<W: Write>(&self, metadata: &EventMetadata, writer: W) -> std::io::Result<()>;
}
