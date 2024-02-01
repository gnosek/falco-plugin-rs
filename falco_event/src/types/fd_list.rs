use crate::event_derive::FromBytesResult;
use crate::from_bytes::FromBytes;
use crate::to_bytes::ToBytes;
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use std::fmt::{Debug, Display, Formatter};
use std::io::Write;

#[derive(Debug, Eq, PartialEq)]
pub struct FdListItem {
    fd: u64,
    flags: u16,
}

#[derive(Debug, Eq, PartialEq)]
pub struct FdList {
    list: Vec<FdListItem>,
}

impl Display for FdList {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for item in &self.list {
            if first {
                first = false;
                write!(f, "[")?;
            } else {
                write!(f, " ")?;
            }
            write!(f, "{}:{:x}", item.fd, item.flags)?
        }

        write!(f, "]")?;
        Ok(())
    }
}

impl ToBytes for FdList {
    fn binary_size(&self) -> usize {
        2 + (8 + 2) * self.list.len()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_u16::<NativeEndian>(self.list.len() as u16)?;
        for item in &self.list {
            item.fd.write(&mut writer)?;
            item.flags.write(&mut writer)?;
        }

        Ok(())
    }

    fn default_repr() -> impl ToBytes {
        0u16
    }
}

impl FromBytes<'_> for FdList {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
        let mut fds = Vec::new();
        let len = buf.read_u16::<NativeEndian>()?;
        for _ in 0..len as usize {
            let fd = u64::from_bytes(buf)?;
            let flags = u16::from_bytes(buf)?;
            fds.push(FdListItem { fd, flags })
        }

        Ok(Self { list: fds })
    }
}

#[cfg(test)]
mod tests {
    use crate::from_bytes::FromBytes;
    use crate::to_bytes::ToBytes;
    use crate::types::fd_list::{FdList, FdListItem};

    #[test]
    fn test_fd_list() {
        let fdlist = FdList {
            list: vec![FdListItem { fd: 13, flags: 1 }],
        };

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
