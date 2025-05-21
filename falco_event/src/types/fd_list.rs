use crate::fields::event_flags::PT_FLAGS16_file_flags;
use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::fmt::{Debug, Formatter};
use std::io::Write;

/// A list of file descriptors with flags
#[derive(Clone, Eq, PartialEq)]
pub struct FdList(pub Vec<(u64, PT_FLAGS16_file_flags)>);

impl Debug for FdList {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for item in &self.0 {
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

impl ToBytes for FdList {
    fn binary_size(&self) -> usize {
        2 + (8 + 2) * self.0.len()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all((self.0.len() as u16).to_ne_bytes().as_slice())?;
        for item in &self.0 {
            item.0.write(&mut writer)?;
            item.1.write(&mut writer)?;
        }

        Ok(())
    }

    fn default_repr() -> impl ToBytes {
        0u16
    }
}

impl FromBytes<'_> for FdList {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError> {
        let mut fds = Vec::new();
        let len_buf = buf.split_off(..2).ok_or(FromBytesError::InvalidLength)?;
        let len = u16::from_ne_bytes(len_buf.try_into().unwrap()) as usize;
        for _ in 0..len {
            let fd = u64::from_bytes(buf)?;
            let flags = PT_FLAGS16_file_flags::from_bytes(buf)?;
            fds.push((fd, flags))
        }

        Ok(Self(fds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_list() {
        let fdlist = FdList(vec![(13, PT_FLAGS16_file_flags::O_RDONLY)]);

        dbg!(&fdlist);

        let mut binary = Vec::new();
        fdlist.write(&mut binary).unwrap();

        assert_eq!(
            binary.as_slice(),
            b"\x01\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x01\x00".as_slice()
        );

        let mut buf = binary.as_slice();

        let fdlist2 = <FdList>::from_bytes(&mut buf).unwrap();

        assert_eq!(fdlist, fdlist2)
    }
}
