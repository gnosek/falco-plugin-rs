use std::fmt::Formatter;
use std::io::Write;
use std::net::Ipv4Addr;

use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;

/// An IPv4 network
///
/// This is a wrapper around [Ipv4Addr] that makes it a distinct type, suitable for storing
/// IPv4 subnets.
pub struct Ipv4Net(pub Ipv4Addr);

impl FromBytes<'_> for Ipv4Net {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
        Ok(Self(Ipv4Addr::from_bytes(buf)?))
    }
}

impl ToBytes for Ipv4Net {
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        Ipv4Addr::default_repr()
    }
}

impl<F> Format<F> for Ipv4Net {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "{}", self.0)
    }
}
