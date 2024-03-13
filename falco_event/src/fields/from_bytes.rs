use thiserror::Error;

#[derive(Error, Debug)]
pub enum FromBytesError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("required field not found")]
    RequiredFieldNotFound,

    #[error("internal NUL in string")]
    InternalNul,

    #[error("missing NUL terminator")]
    MissingNul,

    #[error("truncated event")]
    TruncatedEvent,

    #[error("type mismatch")]
    TypeMismatch,

    #[error("invalid length")]
    InvalidLength,

    #[error("invalid PT_DYN discriminant")]
    InvalidDynDiscriminant,

    #[error("odd item count in pair array")]
    OddPairItemCount,

    #[error("unsupported event type")]
    UnsupportedEventType,
}

pub type FromBytesResult<T> = Result<T, FromBytesError>;

pub trait FromBytes<'a>: Sized {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self>;

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
