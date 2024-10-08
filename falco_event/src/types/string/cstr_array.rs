use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use std::ffi::CStr;
use std::fmt::{Formatter, Write as _};
use std::io::Write;

impl<'a> ToBytes for Vec<&'a CStr> {
    fn binary_size(&self) -> usize {
        self.iter().map(|s| s.binary_size()).sum()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        for s in self {
            s.write(&mut writer)?;
        }

        Ok(())
    }

    fn default_repr() -> impl ToBytes {
        Self::new()
    }
}

impl<'a> FromBytes<'a> for Vec<&'a CStr> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        let mut data = Vec::new();
        while !buf.is_empty() {
            data.push(FromBytes::from_bytes(buf)?);
        }
        Ok(data)
    }
}

impl<'a, F> Format<F> for Vec<&'a CStr>
where
    &'a CStr: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let mut is_first = true;
        for s in self {
            if is_first {
                is_first = false;
            } else {
                fmt.write_char(';')?;
            }

            s.format(fmt)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::event_derive::{FromBytes, ToBytes};
    use std::ffi::CStr;

    #[test]
    fn test_str_array() {
        let arr = vec![
            CStr::from_bytes_until_nul(b"foo\0").unwrap(),
            CStr::from_bytes_until_nul(b"bar\0").unwrap(),
        ];

        let mut binary = Vec::new();
        arr.write(&mut binary).unwrap();

        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), b"foo\0bar\0".as_slice());

        let mut buf = binary.as_slice();
        let loaded = <Vec<&CStr>>::from_bytes(&mut buf).unwrap();

        assert_eq!(arr, loaded)
    }

    #[test]
    fn test_str_empty_array() {
        let arr: Vec<&CStr> = Vec::new();

        let mut binary = Vec::new();
        arr.write(&mut binary).unwrap();

        hexdump::hexdump(binary.as_slice());

        assert!(binary.as_slice().is_empty());

        let mut buf = binary.as_slice();
        let loaded = <Vec<&CStr>>::from_bytes(&mut buf).unwrap();

        assert_eq!(arr, loaded)
    }

    #[test]
    fn test_str_array_with_empty_strings() {
        let mut buf = b"\0\0\0".as_slice();
        let loaded = <Vec<&CStr>>::from_bytes(&mut buf).unwrap();
        assert_eq!(loaded.len(), 3);
        assert!(loaded.iter().all(|s| s.is_empty()))
    }
}
