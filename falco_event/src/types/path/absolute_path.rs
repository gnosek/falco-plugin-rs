use std::ffi::{CStr, OsStr};
use std::fmt::Formatter;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;

impl<'a> FromBytes<'a> for &'a Path {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        let buf = <&CStr>::from_bytes(buf)?;
        let osstr = OsStr::from_bytes(buf.to_bytes());
        Ok(Path::new(osstr))
    }
}

impl ToBytes for &Path {
    fn binary_size(&self) -> usize {
        self.as_os_str().len()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.as_os_str().as_bytes().write(&mut writer)?;
        0u8.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        0u8
    }
}

impl<F> Format<F> for &Path
where
    for<'a> &'a [u8]: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let bytes = self.as_os_str().as_bytes();
        bytes.format(fmt)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    use crate::event_derive::{FromBytes, ToBytes};

    #[test]
    fn test_absolute_path() {
        let path = PathBuf::from_str("/foo").unwrap();
        let mut binary = Vec::new();

        path.as_path().write(&mut binary).unwrap();
        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), "/foo\0".as_bytes());

        let mut buf = binary.as_slice();
        let path = <&Path>::from_bytes(&mut buf).unwrap();
        assert_eq!(path.to_str().unwrap(), "/foo");
    }
}
