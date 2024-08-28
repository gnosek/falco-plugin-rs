use crate::strings::from_ptr::FromPtrError::NullPointer;
use std::ffi::CStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FromPtrError {
    #[error("NULL pointer")]
    NullPointer,

    #[error("UTF-8 error (raw string: {0})")]
    Utf8Error(String),
}

pub(crate) fn try_str_from_ptr<T>(
    ptr: *const std::ffi::c_char,
    _lifetime_donor: &T,
) -> Result<&str, FromPtrError> {
    if ptr.is_null() {
        return Err(NullPointer);
    }

    let cstr = unsafe { CStr::from_ptr(ptr.cast()) };
    cstr.to_str()
        .map_err(|_| FromPtrError::Utf8Error(cstr.to_string_lossy().to_string()))
}
