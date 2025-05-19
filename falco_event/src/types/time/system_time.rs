use crate::fields::{FromBytes, FromBytesError, ToBytes};
use chrono::Local;
use std::io::Write;
use std::time::{Duration, UNIX_EPOCH};

/// System time
///
/// Stored as nanoseconds since epoch
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SystemTime(pub u64);

impl From<std::time::SystemTime> for SystemTime {
    fn from(system_time: std::time::SystemTime) -> Self {
        Self(system_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64)
    }
}

impl SystemTime {
    /// Convert to [`std::time::SystemTime`]
    pub fn to_system_time(&self) -> std::time::SystemTime {
        let duration = Duration::from_nanos(self.0);
        UNIX_EPOCH + duration
    }
}

impl FromBytes<'_> for SystemTime {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError>
    where
        Self: Sized,
    {
        let nanos = u64::from_bytes(buf)?;
        Ok(Self(nanos))
    }
}

impl ToBytes for SystemTime {
    fn binary_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        0u64
    }
}

impl std::fmt::Debug for SystemTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dt = chrono::DateTime::<Local>::from(self.to_system_time());
        f.write_str(&dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false))
    }
}
