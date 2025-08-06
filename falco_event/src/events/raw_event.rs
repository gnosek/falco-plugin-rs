use crate::events::payload::PayloadFromBytesError;
use crate::events::{AnyEventPayload, Event, EventMetadata, EventToBytes};
use crate::fields::{FromBytes, FromBytesError};
use std::io::Write;
use std::marker::PhantomData;
use std::num::TryFromIntError;

/// A trait for types that can be converted from a raw event
pub trait FromRawEvent<'a>: Sized {
    /// Parse a raw event into the type implementing this trait
    fn parse(raw_event: &RawEvent<'a>) -> Result<Self, PayloadFromBytesError>;
}

pub trait LengthField: TryFrom<usize, Error = TryFromIntError> {
    fn read(buf: &mut &[u8]) -> Option<usize>;

    fn to_usize(&self) -> usize;
}

impl LengthField for u16 {
    #[inline]
    fn read(buf: &mut &[u8]) -> Option<usize> {
        let len = buf.split_off(..size_of::<u16>())?;
        Some(u16::from_ne_bytes(len.try_into().unwrap()) as usize)
    }

    #[inline]
    fn to_usize(&self) -> usize {
        *self as usize
    }
}

impl LengthField for u32 {
    #[inline]
    fn read(buf: &mut &[u8]) -> Option<usize> {
        let len = buf.split_off(..size_of::<u32>())?;
        Some(u32::from_ne_bytes(len.try_into().unwrap()) as usize)
    }

    #[inline]
    fn to_usize(&self) -> usize {
        *self as usize
    }
}

pub struct ParamIter<'a, T: LengthField> {
    lengths: &'a [u8],
    params: &'a [u8],
    length_type: PhantomData<T>,
}

impl<'a, T: LengthField> Iterator for ParamIter<'a, T> {
    type Item = Result<&'a [u8], FromBytesError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let len = T::read(&mut self.lengths)?;
        match self.params.split_off(..len) {
            Some(param) => Some(Ok(param)),
            None => Some(Err(FromBytesError::TruncatedField {
                wanted: len,
                got: self.params.len(),
            })),
        }
    }
}

impl<'a, T: LengthField> ParamIter<'a, T> {
    #[inline]
    pub fn next_field<U>(&mut self) -> Result<U, FromBytesError>
    where
        U: FromBytes<'a>,
    {
        let mut maybe_next_field = self.next().transpose()?;
        let val = FromBytes::from_maybe_bytes(maybe_next_field.as_mut())?;
        if let Some(buf) = maybe_next_field {
            if !buf.is_empty() {
                return Err(FromBytesError::LeftoverData);
            }
        }

        Ok(val)
    }
}

/// A raw event, containing the metadata and payload
///
/// This struct is used to represent an event as it is read from a raw byte stream, with
/// minimal parsing of the header. The payload is left as a raw byte buffer, which can be
/// parsed later using the `FromRawEvent` trait.
#[derive(Debug)]
pub struct RawEvent<'a> {
    /// Metadata for the event, including timestamp and thread ID
    pub metadata: EventMetadata,

    /// Length of the event in bytes, including the header
    pub len: u32,

    /// Type of the event, represented as a 16-bit unsigned integer
    pub event_type: u16,

    /// Number of parameters in the event, represented as a 32-bit unsigned integer
    pub nparams: u32,

    /// The payload of the event, containing the raw bytes after the header
    ///
    /// The payload contains `nparams` lengths of either `u16` or `u32` (depending on the event type)
    /// and the actual parameter values. The length of the payload is `len - 26` bytes.
    pub payload: &'a [u8],
}

impl<'e> RawEvent<'e> {
    #[inline]
    fn from_impl(mut buf: &[u8]) -> Option<RawEvent<'_>> {
        let ts_buf = buf.split_off(..8)?;
        let ts = u64::from_ne_bytes(ts_buf.try_into().unwrap());

        let tid_buf = buf.split_off(..8)?;
        let tid = i64::from_ne_bytes(tid_buf.try_into().unwrap());

        let len_buf = buf.split_off(..4)?;
        let len = u32::from_ne_bytes(len_buf.try_into().unwrap());

        let event_type_buf = buf.split_off(..2)?;
        let event_type = u16::from_ne_bytes(event_type_buf.try_into().unwrap());

        let nparams_buf = buf.split_off(..4)?;
        let nparams = u32::from_ne_bytes(nparams_buf.try_into().unwrap());

        Some(RawEvent {
            metadata: EventMetadata { ts, tid },
            len,
            event_type,
            nparams,
            payload: buf,
        })
    }

    /// Parse a byte slice into a RawEvent
    ///
    /// This decodes the header while leaving the payload as a raw byte buffer.
    #[inline]
    pub fn from(buf: &[u8]) -> std::io::Result<RawEvent<'_>> {
        Self::from_impl(buf).ok_or(std::io::ErrorKind::InvalidData.into())
    }

    /// Trim event payload
    ///
    /// This limits the payload to the length actually indicated in the `len` field
    /// and returns the excess data. Useful when reading a raw event stream without
    /// any external structure
    ///
    /// Example
    /// ```
    /// use falco_event::events::{PayloadFromBytesError, RawEvent};
    /// # fn main() -> anyhow::Result<()> {
    /// let mut events: &[u8] = &[ /* raw event bytes */ ];
    ///
    /// while !events.is_empty() {
    ///     let mut event = RawEvent::from(events)?;
    ///     match event.trim() {
    ///         Some(tail) => events = tail,
    ///         None => return Err(PayloadFromBytesError::TruncatedEvent {
    ///             wanted: event.len as usize,
    ///             got: events.len(),
    ///         })?
    ///     }
    /// }
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn trim(&mut self) -> Option<&'e [u8]> {
        let payload_len = self.len as usize - 26;
        self.payload.split_off(payload_len..)
    }

    /// Iterate over a buffer with multiple raw events
    ///
    /// This function takes a byte slice and returns an iterator that yields `RawEvent` instances
    /// until the whole buffer is consumed.
    #[inline]
    pub fn scan(mut buf: &'e [u8]) -> impl Iterator<Item = Result<RawEvent<'e>, std::io::Error>> {
        std::iter::from_fn(move || {
            if buf.is_empty() {
                return None;
            }
            match Self::from(buf) {
                Ok(mut raw_event) => {
                    if let Some(tail) = raw_event.trim() {
                        buf = tail;
                    }
                    Some(Ok(raw_event))
                }

                Err(err) => Some(Err(err)),
            }
        })
    }

    /// Parse a byte buffer (from a raw pointer) into a RawEvent
    ///
    /// # Safety
    ///
    /// `buf` must point to a complete event, i.e.
    ///  - include the length field
    ///  - include `nparams` lengths
    ///  - have enough data bytes for all the fields (sum of lengths)
    #[inline]
    pub unsafe fn from_ptr<'a>(buf: *const u8) -> std::io::Result<RawEvent<'a>> {
        let len_buf = unsafe { std::slice::from_raw_parts(buf.offset(16), 4) };
        let len = u32::from_ne_bytes(len_buf.try_into().unwrap());

        let buf: &'a [u8] = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        Self::from(buf)
    }

    /// Load the event parameters into a strongly typed `Event<T>`
    ///
    /// This method uses the `FromRawEvent` trait to parse the raw event payload into a specific type `T`.
    /// The returned `Event<T>` contains the metadata (copied from the raw event) and the parsed parameters.
    #[inline]
    pub fn load<'a, T: FromRawEvent<'e>>(&'a self) -> Result<Event<T>, PayloadFromBytesError> {
        #[allow(clippy::question_mark)]
        let params = match T::parse(self) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        Ok(Event {
            metadata: self.metadata.clone(),
            params,
        })
    }

    /// Get an iterator over the event parameters
    ///
    /// `T` must correspond to the type of the length field (u16 or u32, depending on the event type)
    #[inline]
    pub fn params<T: LengthField>(&self) -> Result<ParamIter<'e, T>, PayloadFromBytesError> {
        let length_size = size_of::<T>();
        let ll = self.nparams as usize * length_size;

        if self.payload.len() < ll {
            return Err(PayloadFromBytesError::TruncatedEvent {
                wanted: ll,
                got: self.payload.len(),
            });
        }

        let (lengths, params) = self.payload.split_at(ll);

        Ok(ParamIter {
            lengths,
            params,
            length_type: PhantomData,
        })
    }
}

impl<'a, 'b> From<&'a RawEvent<'b>> for RawEvent<'b> {
    #[inline]
    fn from(event: &'a RawEvent<'b>) -> Self {
        Self {
            metadata: event.metadata.clone(),
            len: event.len,
            event_type: event.event_type,
            nparams: event.nparams,
            payload: event.payload,
        }
    }
}

impl EventToBytes for RawEvent<'_> {
    #[inline]
    fn binary_size(&self) -> usize {
        self.len as usize
    }

    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.metadata
            .write_header(self.len, self.event_type, self.nparams, &mut writer)?;
        writer.write_all(self.payload)
    }
}

impl AnyEventPayload for RawEvent<'_> {
    const SOURCES: &'static [Option<&'static str>] = &[];
    const EVENT_TYPES: &'static [u16] = &[];
}
