//! # Helpers to write CStrings
//!
//! The [`std::ffi::CString`] type does not implement [`std::io::Write`] (since it cannot support
//! values containing zero bytes), so we implement our own wrappers.
//!
//! One way is to use [`WriteIntoCString::write_into`], which takes a closure, which then
//! takes a writer.
//!
//! Another is to create a [`CStringWriter`] explicitly.

pub(crate) mod cstring_writer;
pub(crate) mod from_ptr;

pub use cstring_writer::CStringWriter;
pub use cstring_writer::WriteIntoCString;
