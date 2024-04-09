use std::fmt::Debug;

use crate::fields::{FromBytes, FromBytesResult, ToBytes};

macro_rules! newtype {
    ($(#[$attr:meta])* $name:ident($repr:ty)) => {
        $(#[$attr])*
        #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
        pub struct $name(pub $repr);

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
    /// Error number (errno value)
    #[derive(Debug)]
    Errno(u64)
);

newtype!(
    /// A system call number
    #[derive(Debug)]
    SyscallId(u16)
);
newtype!(
    /// A signal number
    #[derive(Debug)]
    SigType(u8)
);
newtype!(
    /// File descriptor
    #[derive(Debug)]
    Fd(i64)
);
newtype!(
    /// Process or thread id
    #[derive(Debug)]
    Pid(i64)
);
newtype!(
    /// User id
    #[derive(Debug)]
    Uid(u32)
);
newtype!(
    /// Group id
    #[derive(Debug)]
    Gid(u32)
);
newtype!(
    /// Signal set (bitmask of signals, only the lower 32 bits are used)
    #[derive(Debug)]
    SigSet(u32)
);
newtype!(
    /// IP port number
    #[derive(Debug)]
    Port(u16)
);
newtype!(
    /// Layer 4 protocol (tcp/udp)
    #[derive(Debug)]
    L4Proto(u8)
);
newtype!(
    /// Socket family (`PPM_AF_*`)
    #[derive(Debug)]
    SockFamily(u8)
);
newtype!(
    /// Boolean value (0/1)
    #[derive(Debug)]
    Bool(u32)
);
