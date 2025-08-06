use crate::fields::{FromBytes, FromBytesError, ToBytes};
use crate::types::format::CStrFormatter;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter, Write as _};
use std::io::Write;

/// A serialized representation of a C-style string array
///
/// This type represents an array of C-style strings, where each string is null-terminated.
/// To get an iterator over the strings, use the `iter` method.
#[derive(Copy, Clone)]
pub struct CStrArray<'a>(&'a [u8]);

/// This is an iterator for CStrArray that allows iterating over the contained C-style strings.
pub struct CStrArrayIter<'a>(&'a [u8]);

impl<'a> Iterator for CStrArrayIter<'a> {
    type Item = &'a CStr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else {
            <&'a CStr>::from_bytes(&mut self.0).ok()
        }
    }
}

impl<'a> CStrArray<'a> {
    /// Return an iterator over the C-style strings in this array
    #[inline]
    pub fn iter(&self) -> CStrArrayIter<'a> {
        CStrArrayIter(self.0)
    }
}

impl ToBytes for CStrArray<'_> {
    #[inline]
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    #[inline]
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        &[] as &[u8]
    }
}

impl<'a> FromBytes<'a> for CStrArray<'a> {
    #[inline]
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        match buf.last() {
            Some(&0) | None => Ok(CStrArray(std::mem::take(buf))),
            _ => Err(FromBytesError::MissingNul),
        }
    }
}

impl Debug for CStrArray<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut is_first = true;
        for s in self.iter() {
            if is_first {
                is_first = false;
            } else {
                f.write_char(';')?;
            }
            Debug::fmt(&CStrFormatter(s), f)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{FromBytes, ToBytes};
    use crate::types::string::cstr_array::CStrArray;

    #[test]
    fn test_str_array() {
        let binary = b"foo\0bar\0".as_slice();
        let array = CStrArray::from_bytes(&mut &*binary).unwrap();

        let mut iter = array.iter();
        assert_eq!(iter.next().unwrap(), c"foo");
        assert_eq!(iter.next().unwrap(), c"bar");
        assert_eq!(iter.next(), None);

        let mut serialized = Vec::new();
        array.write(&mut serialized).unwrap();
        assert_eq!(serialized.as_slice(), binary);
    }

    #[test]
    fn test_str_empty_array() {
        let binary = b"".as_slice();
        let array = CStrArray::from_bytes(&mut &*binary).unwrap();

        let mut iter = array.iter();
        assert_eq!(iter.next(), None);

        let mut serialized = Vec::new();
        array.write(&mut serialized).unwrap();
        assert_eq!(serialized.as_slice(), binary);
    }

    #[test]
    fn test_str_array_with_empty_strings() {
        let binary = b"\0\0\0".as_slice();
        let array = CStrArray::from_bytes(&mut &*binary).unwrap();

        let mut iter = array.iter();
        assert_eq!(iter.next().unwrap(), c"");
        assert_eq!(iter.next().unwrap(), c"");
        assert_eq!(iter.next().unwrap(), c"");
        assert_eq!(iter.next(), None);

        let mut serialized = Vec::new();
        array.write(&mut serialized).unwrap();
        assert_eq!(serialized.as_slice(), binary);
    }
}
