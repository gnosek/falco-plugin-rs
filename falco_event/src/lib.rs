//! # Falco events
//!
//! This crate provides support for working with Falco events:
//!
//! ## Event header
//!
//! ## Raw (untyped) events
//!
//! ## Typed events
//!
//! ### Primitive data types
//!
//! ### Autogenerated enums, bitflags and dynamic value types
//!
//! ### Autogenerated event types
//!
//! ## Serialization and deserialization to/from raw byte buffers
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::fmt::Debug;
use std::io::Write;

use crate::events::EventMetadata;
pub use type_id::TypeId;

use crate::payload::PayloadToBytes;

/// # Autogenerated dynamic field types
///
/// Dynamic fields can have different types based on the context (e.g. the system call parameters).
/// All the implementations in this module are generated from the C structs and mapped to a Rust
/// enum.
#[allow(missing_docs)]
pub mod dynamic_params;
#[allow(missing_docs)]
pub mod event_flags;
#[allow(missing_docs)]
pub mod events;
pub mod fields;
pub mod payload;
pub mod raw_event;
mod type_id;
mod types;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(missing_docs)]
mod ffi;

#[derive(Debug)]
pub struct Event<T> {
    pub metadata: EventMetadata,
    pub params: T,
}

pub trait EventToBytes {
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()>;
}

impl<T: PayloadToBytes> EventToBytes for Event<T> {
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.params.write(&self.metadata, writer)
    }
}

impl<'a> EventToBytes for &'a [u8] {
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self)
    }
}

#[doc(hidden)]
// things for the derive macro to access under a well-known name
pub mod event_derive {
    pub use byteorder::NativeEndian;
    pub use byteorder::ReadBytesExt;
    pub use byteorder::WriteBytesExt;

    pub use crate::events::EventMetadata;
    pub use crate::fields::from_bytes::FromBytes;
    pub use crate::fields::from_bytes::FromBytesError;
    pub use crate::fields::from_bytes::FromBytesResult;
    pub use crate::fields::to_bytes::NoDefault;
    pub use crate::fields::to_bytes::ToBytes;
    pub use crate::fields::types as event_field_type;
    pub use crate::payload::EventPayload;
    pub use crate::payload::PayloadFromBytes;
    pub use crate::payload::PayloadToBytes;
}
