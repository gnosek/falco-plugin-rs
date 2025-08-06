use crate::fields::event_flags::PT_FLAGS16_file_flags;
use falco_event::fields::{FromBytes, FromBytesError, ToBytes};
use std::fmt::{Debug, Formatter};
use std::io::Write;

/// An iterator over all items in a [`FdList`]
///
/// Yields pairs of (fd, flags)
pub struct FdListIter<'a>(&'a [u8]);

impl Iterator for FdListIter<'_> {
    type Item = (u64, PT_FLAGS16_file_flags);

    fn next(&mut self) -> Option<Self::Item> {
        let fd = u64::from_bytes(&mut self.0).ok()?;
        let flags = PT_FLAGS16_file_flags::from_bytes(&mut self.0).ok()?;

        Some((fd, flags))
    }
}

impl ExactSizeIterator for FdListIter<'_> {
    fn len(&self) -> usize {
        self.0.len() / 10 // Each fd and flags pair is 10 bytes
    }
}

/// A list of file descriptors with flags
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FdList<'a>(usize, &'a [u8]);

impl<'a> FdList<'a> {
    /// Return an iterator over the (fd, flags) pairs in this list
    pub fn iter(&self) -> FdListIter<'a> {
        FdListIter(self.1)
    }
}

impl Debug for FdList<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for item in self.iter() {
            if first {
                first = false;
                write!(f, "[")?;
            } else {
                write!(f, " ")?;
            }
            // TODO: this could use a shorter repr (without the bits)
            write!(f, "{}:{:?}", item.0, item.1)?;
        }

        write!(f, "]")?;
        Ok(())
    }
}

impl ToBytes for FdList<'_> {
    fn binary_size(&self) -> usize {
        2 + self.1.len()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all((self.0 as u16).to_ne_bytes().as_slice())?;
        writer.write_all(self.1)?;

        Ok(())
    }

    fn default_repr() -> impl ToBytes {
        0u16
    }
}

impl<'a> FromBytes<'a> for FdList<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        let len = u16::from_bytes(buf)?;

        let payload =
            buf.split_off(..len as usize * 10)
                .ok_or_else(|| FromBytesError::TruncatedField {
                    wanted: 2 + len as usize,
                    got: buf.len(),
                })?;

        Ok(Self(len as usize, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_list() {
        let binary = b"\x01\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x01\x00".as_slice();
        let fdlist = FdList::from_bytes(&mut &*binary).unwrap();

        let mut iter = fdlist.iter();
        assert_eq!(iter.next(), Some((13, PT_FLAGS16_file_flags::O_RDONLY)));
        assert_eq!(iter.next(), None);

        let mut serialized = Vec::new();
        fdlist.write(&mut serialized).unwrap();

        assert_eq!(serialized.as_slice(), binary);
    }
}
