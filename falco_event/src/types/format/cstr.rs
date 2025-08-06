use crate::types::format::ByteBufFormatter;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};

/// Falco-style CStr formatter
///
/// Formats the string like a byte buffer (replacing non-ASCII characters with `.`).
/// See [`ByteBufFormatter`] for the implementation.
pub struct CStrFormatter<'a>(pub &'a CStr);

impl Debug for CStrFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&ByteBufFormatter(self.0.to_bytes()), f)
    }
}
