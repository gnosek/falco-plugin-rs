use std::io::Write;

pub trait ToBytes {
    fn binary_size(&self) -> usize;
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()>;

    fn default_repr() -> impl ToBytes;
}

pub struct NoDefault;

impl ToBytes for NoDefault {
    fn binary_size(&self) -> usize {
        0
    }

    fn write<W: Write>(&self, _writer: W) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "field cannot be empty when writing",
        ))
    }

    fn default_repr() -> impl ToBytes {
        Self
    }
}

impl<T: ToBytes> ToBytes for Option<T> {
    fn binary_size(&self) -> usize {
        if let Some(inner) = &self {
            inner.binary_size()
        } else {
            Self::default_repr().binary_size()
        }
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        match self {
            Some(ref val) => val.write(writer),
            None => T::default_repr().write(writer),
        }
    }

    fn default_repr() -> impl ToBytes {
        T::default_repr()
    }
}
