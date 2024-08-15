use crate::strings::from_ptr::FromPtrError::NullPointer;
use std::ffi::{c_char, CStr};
use thiserror::Error;

#[derive(Error, Debug, Eq, PartialEq)]
pub enum FromPtrError {
    #[error("NULL pointer")]
    NullPointer,

    #[error("UTF-8 error (raw string: {0})")]
    Utf8Error(String),
}

pub(crate) unsafe fn try_str_from_ptr_with_lifetime<T>(
    ptr: *const c_char,
    _lifetime_donor: &T,
) -> Result<&str, FromPtrError> {
    if ptr.is_null() {
        return Err(NullPointer);
    }

    let cstr = unsafe { CStr::from_ptr(ptr.cast()) };
    cstr.to_str()
        .map_err(|_| FromPtrError::Utf8Error(cstr.to_string_lossy().to_string()))
}

pub(crate) fn try_str_from_ptr(ptr: &*const c_char) -> Result<&str, FromPtrError> {
    unsafe { try_str_from_ptr_with_lifetime(*ptr, ptr) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid() {
        let str = c"testing";
        let ptr = str.as_ptr();
        assert_eq!(try_str_from_ptr(&ptr), Ok("testing"));
    }

    #[test]
    fn test_null() {
        let ptr = std::ptr::null();
        assert_eq!(try_str_from_ptr(&ptr), Err(NullPointer));
    }

    #[test]
    fn test_invalid_utf8() {
        let str = c"invalid\xeautf-8";
        let ptr = str.as_ptr();

        match try_str_from_ptr(&ptr) {
            Err(FromPtrError::Utf8Error(s)) if s == "invalid\u{fffd}utf-8" => {}
            _ => panic!("Expected UTF-8 error, got {:?}", try_str_from_ptr(&ptr)),
        }
    }
}
