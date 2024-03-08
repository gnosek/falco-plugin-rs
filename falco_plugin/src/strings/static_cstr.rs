/// # Create a static C-style string
///
/// This macro will be removed once Rust 1.77 is stable, as it's going to support C-style
/// strings natively, using the `c"string contents"` syntax. Until then, use this macro
/// like this instead:
/// ```
/// use std::ffi::CStr;
/// use falco_plugin::c;
/// let foo: &'static CStr = c!("string contents");
/// ```
///
/// and be very careful not to embed NULs in your string.
#[macro_export]
macro_rules! c {
    ($s:expr) => {
        unsafe { ::std::ffi::CStr::from_bytes_with_nul_unchecked(concat!($s, "\0").as_bytes()) }
    };
}
