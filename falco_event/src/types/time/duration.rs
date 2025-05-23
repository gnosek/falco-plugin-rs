use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::io::Write;
use std::time::Duration;

impl FromBytes<'_> for Duration {
    #[inline]
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError>
    where
        Self: Sized,
    {
        let nanos = u64::from_bytes(buf)?;
        Ok(Self::from_nanos(nanos))
    }
}

impl ToBytes for Duration {
    #[inline]
    fn binary_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }

    #[inline]
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        (self.as_nanos() as u64).write(writer)
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        0u64
    }
}
