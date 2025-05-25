#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

/// # Derive event-related traits for an enum
///
/// Use this macro to define an enum like `falco_event::events::types::AnyEvent`, that is usable
/// wherever another event type is. For example,
///
/// ```
/// use std::borrow::Cow;
/// use std::ffi::CStr;
/// use anyhow::{anyhow, Context};
/// use falco_event::events::PayloadFromBytesError;
///
/// #[derive(Default, Debug, falco_event::EventPayload)]
/// #[event_payload(code = 322, length_type = u32)]
/// pub struct MyPluginEvent<'a> {
///     pub plugin_id: u32,
///     pub data: &'a [u8],
/// }
///
/// #[derive(Default, Debug, falco_event::EventPayload)]
/// #[event_payload(code = 322, length_type = u32)]
/// pub struct MyAsyncEvent<'a> {
///     pub plugin_id: u32,
///     pub name: &'a [u8],
///     pub data: &'a [u8],
/// }
///
/// #[derive(falco_event_derive::AnyEvent)]
/// pub enum AnyPluginEvent<'a> {
///     AsyncEvent(MyAsyncEvent<'a>),
///     PluginEvent(MyPluginEvent<'a>),
/// }
/// ```
///
/// If the `falco_event` crate is available under a different path, provide its name
/// in the `falco_event_crate` attribute:
///
/// ```ignore
/// #[derive(falco_event::AnyEvent)]
/// #[falco_event_crate(falco_event_alt)]
/// pub enum AnyPluginEvent<'a> {
///     AsyncEvent(MyAsyncEvent<'a>),
///     PluginEvent(MyPluginEvent<'a>),
/// }
/// ```
///
/// ## Requirements
///
/// To use this macro on an enum, all its variants need to have exactly one unnamed field,
/// which implements the following traits:
/// * [`std::fmt::Debug`], for a string representation
/// * [`events::EventPayload`], which indicates the type id (and source) of the variant
/// * [`events::FromRawEvent`], which handles deserialization of the variant
/// * [`events::PayloadToBytes`], which handles serialization of the variant
///
/// One way to fullfil these requirements is to use the [`EventPayload`]
/// macro on the variant field's type.
///
/// ## Derived traits
///
/// This macro implements the following traits on the enum type:
/// * [`std::fmt::Debug`], by delegating to each variant (without additional wrapping)
/// * [`events::EventPayload`], which describes a whole set of type ids and sources supported
///   by the enum (one for each variant)
/// * [`events::FromRawEvent`], for deserialization
/// * [`events::PayloadToBytes`], for serialization
pub use falco_event_derive::AnyEvent;

#[cfg(feature = "derive_deftly")]
pub use derive_deftly;
/// # Derive event-related traits for a struct
///
/// Use this macro to define new event types. For example, the PPME_PLUGINEVENT_E
/// event could be defined as:
///
/// ```
/// # use std::borrow::Cow;
///
/// #[derive(Default, falco_event::EventPayload)]
/// #[event_payload(code = 322, length_type = u32)]
/// pub struct MyPluginEvent<'a> {
///     pub plugin_id: u32,
///     pub data: &'a [u8],
/// }
/// ```
///
/// If the `falco_event` crate is available under a different path, provide its name
/// in the `falco_event_crate` attribute:
///
/// ```ignore
/// # use std::borrow::Cow;
///
/// #[derive(Default, falco_event::EventPayload)]
/// #[event_payload(code = 322, length_type = u32)]
/// #[falco_event_crate(falco_event_alt)]
/// pub struct MyPluginEvent<'a> {
///     pub plugin_id: u32,
///     pub data: &'a [u8],
/// }
/// ```
///
/// To make your struct usable as an event payload, use the `#[event_payload]` attribute
/// with the following (required) parameters:
/// * `source` (`Option<&str>`) -- the name of the event source, for use in plugin metadata
/// * `code` (u16) -- the raw numeric event type id
/// * `length_type` (u16 or u32) -- the type of parameter length; most events use `u16` but a few
///   notable ones (like PPME_ASYNCEVENT_E and PPME_PLUGINEVENT_E) support larger parameter values
///   and so their length type is `u32`
///
/// This macro can be used only on structs, not enums. Each field of the struct must implement
/// [`fields::FromBytes`] and [`fields::FromBytes`]. Due to the requirements of FieldMeta-based
/// deserialization, the whole struct must also implement [`Default`] and may have at most one
/// lifetime generic parameter.
///
///
/// See above for an example use.
///
/// This variant derives the following traits:
/// * [`events::FromRawEvent`] to provide deserialization
/// * [`events::PayloadToBytes`] to provide serialization
pub use falco_event_derive::EventPayload;
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
