use crate::fields::{FromBytes, FromBytesResult, ToBytes};
use crate::format::FormatType;
use crate::types::format::Format;
use crate::types::{Borrow, BorrowDeref};
use std::fmt::{Debug, Formatter, Write as _};
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

pub struct ByteBufFormatter<'a>(pub &'a [u8]);

impl Debug for ByteBufFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // https://users.rust-lang.org/t/idiomatic-to-implement-the-debug-trait-for-x-syntax/84955
        #[allow(deprecated)]
        if f.flags() & 16 != 0 {
            let mut first = true;
            for c in self.0 {
                if first {
                    first = false;
                } else {
                    write!(f, " ")?;
                }
                write!(f, "{:02x}", *c)?;
            }
        } else {
            for c in self.0 {
                let c = *c;
                if !(b' '..=0x7e).contains(&c) {
                    f.write_char('.')?;
                } else {
                    f.write_char(c as char)?;
                }
            }
        }

        Ok(())
    }
}

impl Format for &[u8] {
    fn format(&self, format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result {
        match format_type {
            FormatType::PF_HEX => write!(fmt, "{:x?}", ByteBufFormatter(self)),
            _ => Debug::fmt(self, fmt),
        }
    }
}

impl Borrow for Vec<u8> {
    type Borrowed<'a> = &'a [u8];

    fn borrow(&self) -> Self::Borrowed<'_> {
        self.as_slice()
    }
}

impl BorrowDeref for Vec<u8> {
    type Target<'c>
        = &'c [u8]
    where
        Self: 'c;

    fn borrow_deref(&self) -> Self::Target<'_> {
        self.as_slice()
    }
}

#[cfg(feature = "serde")]
pub mod serde {
    pub mod bytebuf {
        use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(buf: &[u8], ser: S) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks = UtfChunked::from(buf);
                chunks.serialize(ser)
            } else {
                buf.serialize(ser)
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
            let chunks: OwnedUtfChunked = Deserialize::deserialize(de)?;
            Ok(chunks.into_vec())
        }
    }

    pub mod bytebuf_option {
        use crate::types::utf_chunked::UtfChunked;
        use serde::{Serialize, Serializer};

        pub fn serialize<S: Serializer>(buf: &Option<&[u8]>, ser: S) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks = buf.as_ref().map(|buf| UtfChunked::from(*buf));
                chunks.serialize(ser)
            } else {
                buf.serialize(ser)
            }
        }
    }

    pub mod bytebuf_option_owned {
        use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(buf: &Option<Vec<u8>>, ser: S) -> Result<S::Ok, S::Error> {
            let chunks = buf.as_ref().map(|buf| UtfChunked::from(buf.as_slice()));
            chunks.serialize(ser)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Vec<u8>>, D::Error> {
            let chunks: Option<OwnedUtfChunked> = Deserialize::deserialize(de)?;
            Ok(chunks.map(OwnedUtfChunked::into_vec))
        }
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
