use anyhow::anyhow;
use falco_plugin::event::fields::{FromBytes, FromBytesError, NoDefault, ToBytes};
use falco_plugin::event::EventSource;
use std::io::Write;

#[derive(Debug)]
pub struct Countdown<'a> {
    remaining: usize,
    original: &'a [u8],
}

impl EventSource for Countdown<'_> {
    const SOURCE: Option<&'static str> = Some("countdown");
}

impl ToBytes for Countdown<'_> {
    fn binary_size(&self) -> usize {
        self.original.len()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.original)
    }

    fn default_repr() -> impl ToBytes {
        NoDefault
    }
}

fn ascii_digits_prefix(s: &[u8]) -> &[u8] {
    let end = s
        .iter()
        .position(|&b| !b.is_ascii_digit())
        .unwrap_or(s.len());
    &s[..end]
}

fn parse_number_with_suffix(s: &[u8]) -> Result<usize, FromBytesError> {
    let digits = ascii_digits_prefix(s);
    if digits.is_empty() {
        return Err(FromBytesError::Other(anyhow!("missing number")));
    }
    let mut num = 0usize;
    for &b in digits {
        num = num
            .checked_mul(10)
            .and_then(|n| n.checked_add((b - b'0') as usize))
            .ok_or_else(|| FromBytesError::Other(anyhow!("number overflow")))?;
    }
    Ok(num)
}

impl<'a> FromBytes<'a> for Countdown<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        match parse_number_with_suffix(buf) {
            Ok(remaining) => Ok(Countdown {
                remaining,
                original: std::mem::take(buf),
            }),
            Err(e) => Err(e),
        }
    }
}

impl Countdown<'_> {
    pub fn remaining(&self) -> usize {
        self.remaining
    }
}
