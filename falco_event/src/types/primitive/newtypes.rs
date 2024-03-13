use std::fmt::Debug;

use crate::fields::from_bytes::{FromBytes, FromBytesResult};
use crate::fields::to_bytes::ToBytes;

macro_rules! newtype {
    ($(#[$attr:meta])* $name:ident($repr:ty)) => {
        $(#[$attr])*
        pub struct $name($repr);

        impl FromBytes<'_> for $name {
            fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self>
            where
                Self: Sized,
            {
                Ok(Self(FromBytes::from_bytes(buf)?))
            }
        }

        impl ToBytes for $name {
            fn binary_size(&self) -> usize {
                self.0.binary_size()
            }

            fn write<W: std::io::Write>(&self, writer: W) -> std::io::Result<()> {
                self.0.write(writer)
            }

            fn default_repr() -> impl ToBytes {
                <$repr>::default_repr()
            }
        }
    };
}

// TODO(sdk) some of these might want to be enums but it's probably overkill
// TODO(sdk) we might want fancier Debug reprs but it's not possible to e.g. get an Error or ErrorKind
//           from a raw errno value in stable Rust
newtype!(
    #[derive(Debug)]
    Errno(u64)
);

newtype!(
    #[derive(Debug)]
    SyscallId(u16)
);
newtype!(
    #[derive(Debug)]
    SigType(u8)
);
newtype!(
    #[derive(Debug)]
    Fd(i64)
);
newtype!(
    #[derive(Debug)]
    Pid(i64)
);
newtype!(
    #[derive(Debug)]
    Uid(u32)
);
newtype!(
    #[derive(Debug)]
    Gid(u32)
);
newtype!(
    #[derive(Debug)]
    SigSet(u32)
);
newtype!(
    #[derive(Debug)]
    Port(u16)
);
newtype!(
    #[derive(Debug)]
    L4Proto(u8)
);
newtype!(
    #[derive(Debug)]
    SockFamily(u8)
);
newtype!(
    #[derive(Debug)]
    Bool(u32)
);
