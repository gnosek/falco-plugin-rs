use std::fmt::{Debug, Formatter, Write};

/// Falco-style byte buffer formatter
///
/// The default [`Debug`] impl prints out the buffer as an ASCII string, replacing non-printable
/// characters with dots (`.`).
///
/// The hex debug implementation (`{:x?}`) generates a hex dump of the whole buffer.
pub struct ByteBufFormatter<'a>(pub &'a [u8]);

impl Debug for ByteBufFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // https://users.rust-lang.org/t/idiomatic-to-implement-the-debug-trait-for-x-syntax/84955
        #[allow(deprecated)]
        if f.flags() & 16 != 0 {
            let mut first = true;
            for c in self.0 {
                if first {
                    first = false;
                } else {
                    write!(f, " ")?;
                }
                write!(f, "{:02x}", *c)?;
            }
        } else {
            for c in self.0 {
                let c = *c;
                if !(b' '..=0x7e).contains(&c) {
                    f.write_char('.')?;
                } else {
                    f.write_char(c as char)?;
                }
            }
        }

        Ok(())
    }
}
