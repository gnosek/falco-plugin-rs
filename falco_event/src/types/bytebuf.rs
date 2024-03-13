use crate::fields::{FromBytes, FromBytesResult, ToBytes};
use std::io::Write;

impl<'a> FromBytes<'a> for &'a [u8] {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        Ok(buf)
    }
}

impl ToBytes for &[u8] {
    fn binary_size(&self) -> usize {
        self.len()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self)
    }

    fn default_repr() -> impl ToBytes {
        &[] as &[u8]
    }
}

#[cfg(test)]
mod tests {
    use crate::event_derive::{FromBytes, ToBytes};

    #[test]
    fn test_bytebuf() {
        let data = b"foo".as_slice();
        let mut binary = Vec::new();

        data.write(&mut binary).unwrap();
        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), "foo".as_bytes());

        let mut buf = binary.as_slice();
        let loaded = <&[u8]>::from_bytes(&mut buf).unwrap();
        assert_eq!(loaded, "foo".as_bytes());
    }

    #[test]
    fn test_bytebuf_inner_nul() {
        let data = b"f\0oo".as_slice();
        let mut binary = Vec::new();

        data.write(&mut binary).unwrap();
        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), "f\0oo".as_bytes());

        let mut buf = binary.as_slice();
        let loaded = <&[u8]>::from_bytes(&mut buf).unwrap();
        assert_eq!(loaded, "f\0oo".as_bytes());
    }
}
