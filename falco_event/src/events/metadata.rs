use chrono::Local;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct EventMetadata {
    pub ts: u64,
    pub tid: i64,
}

impl EventMetadata {
    pub fn timestamp(&self) -> Option<SystemTime> {
        if self.ts == u64::MAX {
            None
        } else {
            Some(UNIX_EPOCH + Duration::from_nanos(self.ts))
        }
    }

    /// Write event header
    ///
    /// To form a valid event, after calling this method, the caller must write out the payload
    /// at exactly `len - 26` bytes, containing `nparam` lengths (as the proper type)
    /// and the parameter values themselves.
    pub fn write_header<W: Write>(
        &self,
        len: u32,
        event_type: u16,
        nparams: u32,
        mut writer: W,
    ) -> std::io::Result<()> {
        writer.write_all(self.ts.to_ne_bytes().as_slice())?;
        writer.write_all(self.tid.to_ne_bytes().as_slice())?;

        writer.write_all(len.to_ne_bytes().as_slice())?;
        writer.write_all(event_type.to_ne_bytes().as_slice())?;
        writer.write_all(nparams.to_ne_bytes().as_slice())?;

        Ok(())
    }

    /// Write event header and parameter lengths
    ///
    /// To form a valid event, after calling this method, the caller must write out the payload
    /// for each parameter, `lengths[i]` bytes in length.
    pub fn write_header_with_lengths<W: Write, L: Into<u32> + Copy, const N: usize>(
        &self,
        event_type: u16,
        lengths: [L; N],
        mut writer: W,
    ) -> std::io::Result<()> {
        let len = 26 + // header
            (size_of::<L>() * lengths.len()) as u32 +
            lengths.iter().copied().map(Into::into).sum::<u32>();

        let nparams = lengths.len();

        self.write_header(len, event_type, nparams as u32, &mut writer)?;
        let lengths: &[u8] = unsafe {
            std::slice::from_raw_parts(lengths.as_ptr().cast(), lengths.len() * size_of::<L>())
        };
        writer.write_all(lengths)?;

        Ok(())
    }
}

impl Debug for EventMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(timestamp) = self.timestamp() {
            let dt = chrono::DateTime::<Local>::from(timestamp);
            f.write_str(&dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false))?;
        } else {
            f.write_str("<no timestamp>")?;
        }

        write!(f, " tid={:?}", self.tid)
    }
}

impl Default for EventMetadata {
    fn default() -> Self {
        Self {
            ts: u64::MAX,
            tid: -1,
        }
    }
}
