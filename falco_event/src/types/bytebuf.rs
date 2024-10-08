use crate::fields::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::{format_type, Format};
use std::fmt::{Formatter, Write as _};
use std::io::Write;

impl<'a> FromBytes<'a> for &'a [u8] {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        Ok(std::mem::take(buf))
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

impl Format<format_type::PF_NA> for &[u8] {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        for c in *self {
            let c = *c;
            if !(b' '..=0x7e).contains(&c) {
                fmt.write_char('.')?;
            } else {
                fmt.write_char(c as char)?;
            }
        }

        Ok(())
    }
}

impl Format<format_type::PF_DEC> for &[u8] {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        // this is actually the same as PF_NA
        <Self as Format<format_type::PF_NA>>::format(self, fmt)
    }
}

impl Format<format_type::PF_HEX> for &[u8] {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let mut first = true;
        for c in *self {
            if first {
                first = false;
            } else {
                write!(fmt, " ")?;
            }
            write!(fmt, "{:02x}", *c)?;
        }

        Ok(())
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
