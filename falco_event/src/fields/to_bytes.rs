use std::io::Write;

/// Convert a field to binary representation
pub trait ToBytes {
    /// Return the number of bytes needed to store the field
    fn binary_size(&self) -> usize;

    /// Write the binary representation to `writer`
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()>;

    /// Return the default representation for the field type
    ///
    /// **Note**: this does not need to be the same type as the implementing type.
    /// For example, an empty C-style string can be represented e.g. by returning `0u8`.
    fn default_repr() -> impl ToBytes;
}

/// A pseudo-field that cannot be written (returns an error at runtime)
///
/// This is useful for types that do not have a default representation (e.g. `PT_DYN` types)
///
/// **Note**: all event fields are generated as `Option<T>`, so there is always a possibility
/// that we get to write a default value for a field that does not have one.
pub struct NoDefault;

impl ToBytes for NoDefault {
    #[inline]
    fn binary_size(&self) -> usize {
        0
    }

    #[inline]
    fn write<W: Write>(&self, _writer: W) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "field cannot be empty when writing",
        ))
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        Self
    }
}

impl<T: ToBytes> ToBytes for Option<T> {
    #[inline]
    fn binary_size(&self) -> usize {
        if let Some(inner) = &self {
            inner.binary_size()
        } else {
            Self::default_repr().binary_size()
        }
    }

    #[inline]
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        match self {
            Some(val) => val.write(writer),
            None => T::default_repr().write(writer),
        }
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        T::default_repr()
    }
}
