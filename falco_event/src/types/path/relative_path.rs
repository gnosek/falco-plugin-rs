use std::io::Write;
use std::path::Path;

use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};

// TODO(sdk) not really trivial to use DIRFD_PARAM :)
//      might need a dedicated generated method on the event type
#[derive(Debug)]
pub struct RelativePath<'a, const DIRFD_PARAM: usize> {
    rel_path: &'a Path,
}

impl<'a, const DIRFD_PARAM: usize> ToBytes for RelativePath<'a, DIRFD_PARAM> {
    fn binary_size(&self) -> usize {
        self.rel_path.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.rel_path.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        <&'a Path>::default_repr()
    }
}

impl<'a, const DIRFD_PARAM: usize> FromBytes<'a> for RelativePath<'a, DIRFD_PARAM> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        Ok(Self {
            rel_path: <&'a Path>::from_bytes(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use crate::event_derive::{FromBytes, ToBytes};
    use crate::types::path::relative_path::RelativePath;

    #[test]
    fn test_relative_path() {
        let path = PathBuf::from_str("/foo").unwrap();
        let rel_path = RelativePath::<'_, 0usize> {
            rel_path: path.as_path(),
        };
        let mut binary = Vec::new();

        rel_path.write(&mut binary).unwrap();
        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), "/foo\0".as_bytes());

        let mut buf = binary.as_slice();
        let path = <RelativePath<'_, 0usize>>::from_bytes(&mut buf).unwrap();
        assert_eq!(path.rel_path.to_str().unwrap(), "/foo");
    }
}
