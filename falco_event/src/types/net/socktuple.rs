use std::fmt::{Debug, Display, Formatter};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use byteorder::{ReadBytesExt, WriteBytesExt};

use crate::ffi::{PPM_AF_INET, PPM_AF_INET6, PPM_AF_LOCAL};
use crate::fields::from_bytes::{FromBytes, FromBytesResult};
use crate::fields::to_bytes::ToBytes;

#[derive(Debug, Eq, PartialEq)]
pub struct EndpointV4(Ipv4Addr, u16);
impl Display for EndpointV4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}

impl ToBytes for EndpointV4 {
    fn binary_size(&self) -> usize {
        self.0.binary_size() + self.1.binary_size()
    }

    //noinspection DuplicatedCode
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.0.write(&mut writer)?;
        self.1.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        Self(Ipv4Addr::from(0), 0)
    }
}

impl FromBytes<'_> for EndpointV4 {
    fn from_bytes(buf: &mut &'_ [u8]) -> FromBytesResult<Self> {
        Ok(Self(
            FromBytes::from_bytes(buf)?,
            FromBytes::from_bytes(buf)?,
        ))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EndpointV6(Ipv6Addr, u16);

impl Display for EndpointV6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]:{}", self.0, self.1)
    }
}

impl ToBytes for EndpointV6 {
    fn binary_size(&self) -> usize {
        self.0.binary_size() + self.1.binary_size()
    }

    //noinspection DuplicatedCode
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.0.write(&mut writer)?;
        self.1.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        Self(Ipv6Addr::from(0), 0)
    }
}

impl FromBytes<'_> for EndpointV6 {
    fn from_bytes(buf: &mut &'_ [u8]) -> FromBytesResult<Self> {
        Ok(Self(
            FromBytes::from_bytes(buf)?,
            FromBytes::from_bytes(buf)?,
        ))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SockTuple<'a> {
    None,
    Unix {
        source_addr: u64,
        dest_addr: u64,
        path: &'a Path,
    },
    V4 {
        source: EndpointV4,
        dest: EndpointV4,
    },
    V6 {
        source: EndpointV6,
        dest: EndpointV6,
    },
    Other(u8, &'a [u8]),
}

impl Display for SockTuple<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SockTuple::None => write!(f, "None"),
            SockTuple::Unix {
                source_addr,
                dest_addr,
                path,
            } => write!(f, "{:x}->{:x} {}", source_addr, dest_addr, path.display()),
            SockTuple::V4 { source, dest } => write!(f, "{:?} -> {:?}", source, dest),
            SockTuple::V6 { source, dest } => write!(f, "{:?} -> {:?}", source, dest),
            SockTuple::Other(af, buf) => f
                .debug_struct("SockTuple")
                .field("af", &af)
                .field("addr", buf)
                .finish(),
        }
    }
}

impl ToBytes for SockTuple<'_> {
    fn binary_size(&self) -> usize {
        match self {
            SockTuple::None => 0,
            SockTuple::Unix {
                source_addr,
                dest_addr,
                path,
            } => 1 + source_addr.binary_size() + dest_addr.binary_size() + path.binary_size(),
            SockTuple::V4 { source, dest } => 1 + source.binary_size() + dest.binary_size(),
            SockTuple::V6 { source, dest } => 1 + source.binary_size() + dest.binary_size(),
            SockTuple::Other(_, buf) => 1 + buf.len(),
        }
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        match self {
            SockTuple::None => Ok(()),
            SockTuple::Unix {
                source_addr,
                dest_addr,
                path,
            } => {
                writer.write_u8(PPM_AF_LOCAL as u8)?;
                source_addr.write(&mut writer)?;
                dest_addr.write(&mut writer)?;
                path.write(writer)
            }
            SockTuple::V4 { source, dest } => {
                writer.write_u8(PPM_AF_INET as u8)?;
                source.write(&mut writer)?;
                dest.write(writer)
            }
            SockTuple::V6 { source, dest } => {
                writer.write_u8(PPM_AF_INET6 as u8)?;
                source.write(&mut writer)?;
                dest.write(writer)
            }
            SockTuple::Other(af, buf) => {
                writer.write_u8(*af)?;
                ToBytes::write(buf, writer)
            }
        }
    }

    fn default_repr() -> impl ToBytes {
        Self::None
    }
}

impl<'a> FromBytes<'a> for SockTuple<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        let variant = buf.read_u8()?;
        match variant as u32 {
            PPM_AF_LOCAL => Ok(Self::Unix {
                source_addr: FromBytes::from_bytes(buf)?,
                dest_addr: FromBytes::from_bytes(buf)?,
                path: FromBytes::from_bytes(buf)?,
            }),
            PPM_AF_INET => Ok(Self::V4 {
                source: FromBytes::from_bytes(buf)?,
                dest: FromBytes::from_bytes(buf)?,
            }),
            PPM_AF_INET6 => Ok(Self::V6 {
                source: FromBytes::from_bytes(buf)?,
                dest: FromBytes::from_bytes(buf)?,
            }),
            _ => Ok(Self::Other(variant, buf)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_socktuple_ipv4() {
        let socktuple = SockTuple::V4 {
            source: EndpointV4(Ipv4Addr::from_str("172.31.33.48").unwrap(), 47263),
            dest: EndpointV4(Ipv4Addr::from_str("172.31.0.2").unwrap(), 53),
        };

        dbg!(&socktuple);

        let mut binary = Vec::new();
        socktuple.write(&mut binary).unwrap();

        assert_eq!(
            binary.as_slice(),
            b"\x02\xac\x1f!0\x9f\xb8\xac\x1f\x00\x025\x00".as_slice()
        );

        let mut buf = binary.as_slice();
        let socktuple2 = <SockTuple>::from_bytes(&mut buf).unwrap();
        assert_eq!(socktuple, socktuple2)
    }

    #[test]
    fn test_socktuple_ipv6() {
        let socktuple = SockTuple::V6 {
            source: EndpointV6(Ipv6Addr::from_str("2001:4860:4860::8844").unwrap(), 47263),
            dest: EndpointV6(Ipv6Addr::from_str("2001:4860:4860::8800").unwrap(), 53),
        };

        dbg!(&socktuple);

        let mut binary = Vec::new();
        socktuple.write(&mut binary).unwrap();

        assert_eq!(
            binary.as_slice(),
            b"\x0a\x20\x01\x48\x60\x48\x60\0\0\0\0\0\0\0\0\x88\x44\x9f\xb8\x20\x01\x48\x60\x48\x60\0\0\0\0\0\0\0\0\x88\x00\x35\x00".as_slice()
        );

        let mut buf = binary.as_slice();
        let socktuple2 = <SockTuple>::from_bytes(&mut buf).unwrap();
        assert_eq!(socktuple, socktuple2)
    }

    #[test]
    fn test_socktuple_unix() {
        let binary = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00 \xcfN\xbc\x98\xff\xff/var/run/nscd/socket\x00".as_slice();
        let mut buf = binary;

        let socktuple = <SockTuple>::from_bytes(&mut buf).unwrap();
        dbg!(&socktuple);

        let mut binary2 = Vec::new();
        socktuple.write(&mut binary2).unwrap();

        let SockTuple::Unix {
            source_addr,
            dest_addr,
            path,
        } = socktuple
        else {
            panic!("not a unix sock tuple: {:?}", socktuple)
        };

        assert_eq!(source_addr, 0);
        assert_eq!(dest_addr, 0xffff98bc4ecf2000);
        assert_eq!(
            path.as_os_str().as_bytes(),
            b"/var/run/nscd/socket".as_slice()
        );

        assert_eq!(binary, binary2.as_slice(),);
    }
}
