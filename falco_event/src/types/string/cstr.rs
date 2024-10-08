use crate::event_derive::{FromBytes, FromBytesError, FromBytesResult, ToBytes};
use crate::types::format::Format;
use std::ffi::{CStr, CString};
use std::fmt::Formatter;
use std::io::Write;

impl<'a> FromBytes<'a> for &'a CStr {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        let cstr = CStr::from_bytes_until_nul(buf).map_err(|_| FromBytesError::MissingNul)?;
        let len = cstr.to_bytes().len();
        *buf = &buf[len + 1..];
        Ok(cstr)
    }
}

impl ToBytes for &CStr {
    fn binary_size(&self) -> usize {
        self.to_bytes().len() + 1
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.to_bytes_with_nul())
    }

    fn default_repr() -> impl ToBytes {
        0u8
    }
}

impl<F> Format<F> for &CStr
where
    for<'a> &'a [u8]: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let bytes = self.to_bytes();
        bytes.format(fmt)
    }
}

impl ToBytes for CString {
    fn binary_size(&self) -> usize {
        self.as_c_str().binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.as_c_str().write(writer)
    }

    fn default_repr() -> impl ToBytes {
        0u8
    }
}

impl<F> Format<F> for CString
where
    for<'a> &'a [u8]: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let bytes = self.as_bytes();
        bytes.format(fmt)
    }
}

#[cfg(test)]
mod tests {
    use crate::event_derive::{FromBytes, ToBytes};
    use std::ffi::CStr;

    #[test]
    fn test_cstr() {
        let s = CStr::from_bytes_until_nul(b"foo\0").unwrap();

        let mut binary = Vec::new();
        s.write(&mut binary).unwrap();

        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), b"foo\0".as_slice());

        let mut buf = binary.as_slice();
        let s2 = <&CStr>::from_bytes(&mut buf).unwrap();

        assert_eq!(s2.to_bytes_with_nul(), b"foo\0".as_slice());
        assert_eq!(buf.len(), 0);
    }
}
