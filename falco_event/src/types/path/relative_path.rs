use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use crate::types::{Borrow, Borrowed};
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// A relative path
///
/// Events containing a parameter of this type will have an extra method available, derived
/// from the field name. For example, if the field is called `name`, the event type will have
/// a method called `name_dirfd` that returns the corresponding `dirfd` (as an `Option<PT_FD>`)
#[derive(Debug, Serialize)]
pub struct RelativePath<'a>(pub &'a Path);

impl<'a> ToBytes for RelativePath<'a> {
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        <&'a Path>::default_repr()
    }
}

impl<'a> FromBytes<'a> for RelativePath<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        Ok(Self(<&'a Path>::from_bytes(buf)?))
    }
}

impl<'a, F> Format<F> for RelativePath<'a>
where
    &'a [u8]: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "<...>")?;

        let bytes = self.0.as_os_str().as_bytes();
        bytes.format(fmt)
    }
}
/// A relative path
///
/// Events containing a parameter of this type will have an extra method available, derived
/// from the field name. For example, if the field is called `name`, the event type will have
/// a method called `name_dirfd` that returns the corresponding `dirfd` (as an `Option<PT_FD>`)
#[derive(Debug, Deserialize, Serialize)]
pub struct OwnedRelativePath(pub PathBuf);

impl<'a> Borrowed for RelativePath<'a> {
    type Owned = OwnedRelativePath;
}

impl Borrow for OwnedRelativePath {
    type Borrowed<'b> = RelativePath<'b>;

    fn borrow(&self) -> Self::Borrowed<'_> {
        RelativePath(self.0.as_path())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    use crate::event_derive::{FromBytes, ToBytes};
    use crate::types::path::relative_path::RelativePath;
    use crate::types::OwnedRelativePath;

    #[test]
    fn test_relative_path() {
        let path = PathBuf::from_str("/foo").unwrap();
        let rel_path = RelativePath(path.as_path());
        let mut binary = Vec::new();

        rel_path.write(&mut binary).unwrap();
        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), "/foo\0".as_bytes());

        let mut buf = binary.as_slice();
        let path = RelativePath::from_bytes(&mut buf).unwrap();
        assert_eq!(path.0.to_str().unwrap(), "/foo");
    }

    #[test]
    fn test_serde_relative_path() {
        let path = RelativePath(Path::new("/foo"));

        let json = serde_json::to_string(&path).unwrap();
        assert_eq!(json, "\"/foo\"");

        let path2: OwnedRelativePath = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&path2).unwrap();
        assert_eq!(json, json2);
    }
}
