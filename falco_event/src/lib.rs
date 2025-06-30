#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "derive_deftly")]
pub use derive_deftly;
pub use num_traits;

#[allow(missing_docs)]
pub mod events;

/// All the types available in event fields
pub mod fields;
mod types;

/// Formatting wrappers
///
/// This module provides wrappers for various types that format the inner type according
/// to Falco style.
pub mod format {
    pub use crate::types::format::OptionFormatter;
    pub use crate::types::ByteBufFormatter;
    pub use crate::types::CStrFormatter;
}

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(missing_docs)]
#[allow(unsafe_op_in_unsafe_fn)]
#[doc(hidden)]
pub mod ffi;
