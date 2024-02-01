use memchr::memchr;
use std::ffi::CString;
use std::fmt::{Debug, Formatter};
use std::io::Write;

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
    pub fn into_cstring(mut self) -> CString {
        self.0.push(0);

        // SAFETY: we disallow embedded NULs on write and add the trailing NUL just above
        //         so the vector contains exactly one NUL, at the end
        unsafe { CString::from_vec_with_nul_unchecked(self.0) }
    }

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
