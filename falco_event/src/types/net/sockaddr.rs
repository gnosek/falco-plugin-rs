use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::ffi::{PPM_AF_INET, PPM_AF_INET6, PPM_AF_LOCAL, PPM_AF_UNSPEC};
use crate::types::{EndpointV4, EndpointV6};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// A socket address
#[derive(Debug)]
pub enum SockAddr<'a> {
    /// Unix sockets
    Unix(&'a Path),

    /// IPv4 sockets
    V4(EndpointV4),

    /// IPv6 socket
    V6(EndpointV6),

    /// any other address family is represented as the number (`PPM_AF_*` constant) and the raw data
    Other(u8, &'a [u8]),
}

impl ToBytes for SockAddr<'_> {
    fn binary_size(&self) -> usize {
        match self {
            SockAddr::Unix(p) => 1 + p.binary_size(),
            SockAddr::V4(addr) => 1 + addr.binary_size(),
            SockAddr::V6(addr) => 1 + addr.binary_size(),
            SockAddr::Other(_, buf) => 1 + buf.len(),
        }
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        match self {
            SockAddr::Unix(p) => {
                writer.write_u8(PPM_AF_LOCAL as u8)?;
                p.write(writer)
            }
            SockAddr::V4(addr) => {
                writer.write_u8(PPM_AF_INET as u8)?;
                addr.write(writer)
            }
            SockAddr::V6(addr) => {
                writer.write_u8(PPM_AF_INET6 as u8)?;
                addr.write(writer)
            }
            SockAddr::Other(af, addr) => {
                writer.write_u8(*af)?;
                ToBytes::write(addr, writer)
            }
        }
    }

    fn default_repr() -> impl ToBytes {
        PPM_AF_UNSPEC as u8
    }
}

impl<'a> FromBytes<'a> for SockAddr<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        let variant = buf.read_u8()?;
        match variant as u32 {
            PPM_AF_LOCAL => {
                let path = <OsStr as OsStrExt>::from_bytes(buf);
                *buf = &[];
                Ok(Self::Unix(Path::new(path)))
            }
            PPM_AF_INET => {
                let addr = EndpointV4::from_bytes(buf)?;
                Ok(Self::V4(addr))
            }
            PPM_AF_INET6 => {
                let addr = EndpointV6::from_bytes(buf)?;
                Ok(Self::V6(addr))
            }
            _ => Ok(Self::Other(variant, buf)),
        }
    }
}
