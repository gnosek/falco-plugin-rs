use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use std::io::Write;
use std::net::IpAddr;

pub struct IpNet(pub IpAddr);

impl FromBytes<'_> for IpNet {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
        Ok(Self(IpAddr::from_bytes(buf)?))
    }
}

impl ToBytes for IpNet {
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        IpAddr::default_repr()
    }
}
