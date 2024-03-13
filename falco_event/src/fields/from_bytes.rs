use thiserror::Error;

/// Error type for deserializing data from a byte buffer
#[derive(Error, Debug)]
pub enum FromBytesError {
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Required field not found
    #[error("required field not found")]
    RequiredFieldNotFound,

    /// NUL inside a string
    #[error("internal NUL in string")]
    InternalNul,

    /// Missing NUL terminator
    #[error("missing NUL terminator")]
    MissingNul,

    /// Truncated event
    #[error("truncated event")]
    TruncatedEvent,

    /// Type mismatch
    #[error("type mismatch")]
    TypeMismatch,

    /// Invalid length
    #[error("invalid length")]
    InvalidLength,

    /// Invalid PT_DYN discriminant
    #[error("invalid PT_DYN discriminant")]
    InvalidDynDiscriminant,

    /// Odd item count in pair array
    #[error("odd item count in pair array")]
    OddPairItemCount,

    /// Unsupported event type
    #[error("unsupported event type")]
    UnsupportedEventType,
}

/// The result of a deserialization
pub type FromBytesResult<T> = Result<T, FromBytesError>;

/// Deserialize a field from a byte buffer
pub trait FromBytes<'a>: Sized {
    /// Read the binary representation of a field and return the parsed representation
    ///
    /// **Note**: the argument is a mutable reference to an immutable slice. While the contents
    /// of the slice cannot be modified, the slice itself can. Every call to `from_bytes` consumes
    /// a number of bytes from the beginning of the slice.
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self>;

    /// Read the binary representation of a field from a buffer that may or may not exist
    ///
    /// The default implementation returns an error when the buffer does not exist, but the blanket
    /// impl for `Option<T>` effectively returns `Ok(None)`
    fn from_maybe_bytes(buf: Option<&mut &'a [u8]>) -> FromBytesResult<Self> {
        match buf {
            Some(buf) => Self::from_bytes(buf),
            None => Err(FromBytesError::RequiredFieldNotFound),
        }
    }
}

impl<'a, T: FromBytes<'a> + 'a> FromBytes<'a> for Option<T>
where
    T: Sized,
{
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        T::from_bytes(buf).map(Some)
    }

    fn from_maybe_bytes(buf: Option<&mut &'a [u8]>) -> FromBytesResult<Self> {
        buf.map(T::from_bytes).transpose()
    }
}
