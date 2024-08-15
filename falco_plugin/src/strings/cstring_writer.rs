use memchr::memchr;
use std::ffi::CString;
use std::fmt::{Debug, Formatter};
use std::io::Write;

/// # A helper that enables writing into CStrings
///
/// This type implements [`Write`] and yields a [`CString`] at the end,
/// which is useful for generating string data to be shared with the Falco
/// plugin framework.
///
/// The [`Write`] implementation returns an error whenever the data to be written
/// contains a NUL byte.
///
/// Example:
/// ```
/// use std::ffi::CString;
/// use falco_plugin::source::CStringWriter;
/// use std::io::Write;
/// let mut writer = CStringWriter::default();
///
/// write!(writer, "Hello, world, five={}", 5)?;
///
/// let output: CString = writer.into_cstring();
/// # Result::<(), std::io::Error>::Ok(())
/// ```
#[derive(Default)]
pub struct CStringWriter(Vec<u8>);

impl Debug for CStringWriter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CStringWriter")
            .field(&String::from_utf8_lossy(self.0.as_slice()))
            .finish()
    }
}

impl Write for CStringWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if memchr(0, buf).is_some() {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "NUL in data",
            ))
        } else {
            self.0.write(buf)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl CStringWriter {
    /// # Finalize the writer object and return a [`CString`]
    ///
    /// This method consumes the CStringWriter and returns a CString
    /// containing all the written data
    pub fn into_cstring(mut self) -> CString {
        self.0.push(0);

        // SAFETY: we disallow embedded NULs on write and add the trailing NUL just above
        //         so the vector contains exactly one NUL, at the end
        unsafe { CString::from_vec_with_nul_unchecked(self.0) }
    }

    /// # Finalize the writer object and store the output in a [`CString`]
    ///
    /// This method consumes the CStringWriter, but instead of returning
    /// a CString, it stores the output in an existing CString (replacing
    /// any previous content).
    pub fn store(self, target: &mut CString) {
        let mut s = self.into_cstring();
        std::mem::swap(&mut s, target)
    }
}

pub trait WriteIntoCString {
    fn write_into<F>(&mut self, func: F) -> std::io::Result<()>
    where
        F: FnOnce(&mut CStringWriter) -> std::io::Result<()>;
}

impl WriteIntoCString for CString {
    fn write_into<F>(&mut self, func: F) -> std::io::Result<()>
    where
        F: FnOnce(&mut CStringWriter) -> std::io::Result<()>,
    {
        let mut w = CStringWriter::default();
        func(&mut w)?;
        w.store(self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_store() {
        let mut buf = CString::default();

        let mut writer = CStringWriter::default();
        write!(writer, "hello").unwrap();
        #[allow(clippy::write_literal)]
        write!(writer, ", {}", "world").unwrap();
        writer.flush().unwrap();

        writer.store(&mut buf);

        assert_eq!(buf.as_c_str(), c"hello, world");
    }

    #[test]
    fn test_invalid_store() {
        let mut writer = CStringWriter::default();
        write!(writer, "hell\0o").unwrap_err();
    }

    #[test]
    fn test_valid_write_into() {
        let mut buf = CString::default();

        buf.write_into(|w| write!(w, "hello")).unwrap();

        assert_eq!(buf.as_c_str(), c"hello");
    }

    #[test]
    fn test_invalid_write_into() {
        let mut buf = CString::default();

        buf.write_into(|w| write!(w, "hell\0o")).unwrap_err();
    }
}
