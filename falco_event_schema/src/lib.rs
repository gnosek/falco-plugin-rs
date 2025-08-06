#![doc = include_str!("../README.md")]

#[cfg(feature = "derive_deftly")]
pub use derive_deftly;

/// All the types available in event fields
pub mod fields;
mod types;

/// # Event types
///
/// This module is automatically generated from the Falco event schema. It provides strongly-typed
/// structs for each event type supported by Falco, as well as a [`events::AnyEvent`] enum that is capable
/// of containing an arbitrary event matching the schema.
#[allow(clippy::crate_in_macro_def)]
pub mod events;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(missing_docs)]
#[allow(unsafe_op_in_unsafe_fn)]
#[doc(hidden)]
pub mod ffi;

#[cfg(test)]
mod tests;
