use std::io::Write;
use std::net::Ipv6Addr;

use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};

pub struct Ipv6Net(pub Ipv6Addr);

impl FromBytes<'_> for Ipv6Net {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
        Ok(Self(Ipv6Addr::from_bytes(buf)?))
    }
}

impl ToBytes for Ipv6Net {
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        Ipv6Addr::default_repr()
    }
}
