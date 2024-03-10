#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! # Falco plugin SDK
//!
//! This crate provides a framework for writing [Falco](https://github.com/falcosecurity/falco)
//! plugins. There are several types of plugins available. Learn more about Falco plugins
//! and plugin types in the [Falco plugin documentation](https://falco.org/docs/plugins/).
//!
//! Since Falco plugins are distributed as shared libraries, they must be built
//! with `crate_type = ["dylib"]`.
//!
//! All plugins must implement the base plugin trait (see [`base`]) and at least one of the plugin
//! capabilities.
//!
//! **Note**: due to the structure of the Falco plugin API, there can be only one plugin per shared
//! library, though that plugin can implement multiple capabilities, as described below.
//!
//! ### Event sourcing plugins
//!
//! Source plugins are used to generate events. The implementation comes in two parts:
//!
//! 1. An implementation of [`source::SourcePlugin`] on the plugin type, which mostly serves
//!    to create a plugin instance
//! 2. A type implementing [`source::SourcePluginInstance`], which does the actual event generation
//!
//! To register your plugin's event sourcing capability, pass it to the [`source_plugin!`] macro.
//!
//! See `samples/source_plugin.rs` for an example implementation.
//!
//! ### Field extraction plugins
//!
//! Field extraction plugins add extra fields to be used in rule matching and rule output. Each
//! field has a name, type and a function or method that returns the actual extracted data.
//! Extraction plugins are created by implementing the [`extract::ExtractPlugin`] trait.
//!
//! See `samples/extract_plugin.rs` for an example implementation.
//!
//! ### Event parsing plugins
//!
//! Event parsing plugins are invoked on every event (modulo some filtering) and can be used to
//! maintain some state across events, e.g. for extraction plugins our source plugins to return
//! later. They are created by implementing [`parse::ParsePlugin`] and calling [`parse_plugin!`]
//! with the plugin type.
//!
//! See `samples/parse_plugin.rs` for an example implementation.
//!
//! ### Asynchronous event plugins
//!
//! Asynchronous event plugins can be used to inject events outside the flow of the main event loop,
//! for example from a separate thread. They are created by implementing [`async_event::AsyncEventPlugin`]
//! and calling [`async_event_plugin!`] with the plugin type.
//!
//! See `samples/async_plugin.rs` for an example implementation.

// #![deny(clippy::undocumented_unsafe_blocks)]
// reexport dependencies
pub use schemars;
pub use serde;

pub use crate::plugin::error::FailureReason;
pub use crate::plugin::event::EventInput;

/// # The common foundation for all Falco plugins
///
/// All plugins must implement the [`base::Plugin`] trait which specifies some basic metadata
/// about the plugin. For example, a plugin that doesn't support any capabilities (which is
/// useless and would fail to load, but is a necessary step to building an actually useful plugin)
/// might look like:
///
/// ```
/// use std::ffi::CStr;
/// use falco_plugin::base::{InitInput, Plugin};
/// use falco_plugin::{c, plugin};
/// use falco_plugin::FailureReason;
///
/// // define the type holding the plugin state
/// struct NoOpPlugin;
///
/// // implement the base::Plugin trait
/// impl Plugin for NoOpPlugin {
///     const NAME: &'static CStr = c!("sample-plugin-rs");
///     const PLUGIN_VERSION: &'static CStr = c!("0.0.1");
///     const DESCRIPTION: &'static CStr = c!("A sample Falco plugin that does nothing");
///     const CONTACT: &'static CStr = c!("you@example.com");
///     type ConfigType = ();
///
///     fn new(input: &InitInput, config: Self::ConfigType)
///         -> Result<Self, FailureReason> {
///         Ok(NoOpPlugin)
///     }
/// }
///
/// // generate the actual plugin wrapper code
/// plugin!(NoOpPlugin);
/// ```
///
/// See the [`base::Plugin`] trait documentation for details.
pub mod base {
    /// The plugin init input from the Falco plugin framework
    ///
    /// The notable thing about this type is that it implements [`TableInitInput`]. You should not
    /// need to access its fields directly.
    pub use falco_plugin_api::ss_plugin_init_input as InitInput;

    pub use crate::plugin::base::Plugin;
    pub use crate::plugin::schema::Json;
    pub use crate::plugin::tables::ffi::InitInput as TableInitInput;
}

/// # Field extraction plugin support
///
/// For your plugin to support field extraction, you will need to implement the [`extract::ExtractPlugin`]
/// trait, for example:
///
/// ```
/// use std::ffi::{CStr, CString};
/// use anyhow::Error;
/// use falco_event::EventType;
/// use falco_plugin::base::{InitInput, Plugin};
/// use falco_plugin::{c, extract_plugin, FailureReason, plugin};
/// use falco_plugin::extract::{
///     EventInput,
///     ExtractFieldInfo,
///     ExtractFieldRequestArg,
///     ExtractPlugin,
///     field};
/// use falco_plugin::tables::TableReader;
///
/// struct MyExtractPlugin;
/// impl Plugin for MyExtractPlugin {
///     // ...
/// #    const NAME: &'static CStr = c!("sample-plugin-rs");
/// #    const PLUGIN_VERSION: &'static CStr = c!("0.0.1");
/// #    const DESCRIPTION: &'static CStr = c!("A sample Falco plugin that does nothing");
/// #    const CONTACT: &'static CStr = c!("you@example.com");
/// #    type ConfigType = ();
/// #
/// #    fn new(input: &InitInput, config: Self::ConfigType)
/// #        -> Result<Self, FailureReason> {
/// #        Ok(MyExtractPlugin)
/// #    }
/// }
///
/// impl MyExtractPlugin { // note this is not the trait implementation
///     fn extract_sample(
///         &mut self,
///         _context: &mut (),
///         _arg: ExtractFieldRequestArg,
///         _input: &EventInput,
///         _tables: &TableReader,
///     ) -> Result<CString, Error> {
///         Ok(c!("hello").to_owned())
///     }
/// }
///
/// impl ExtractPlugin for MyExtractPlugin {
///     const EVENT_TYPES: &'static [EventType] = &[]; // all event types
///     const EVENT_SOURCES: &'static [&'static str] = &[]; // all event sources
///     type ExtractContext = ();
///
///     const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
///         field("my_extract.sample", &Self::extract_sample),
///     ];
/// }
///
/// plugin!(MyExtractPlugin);
/// extract_plugin!(MyExtractPlugin);
/// ```
///
/// See the [`extract::ExtractPlugin`] trait documentation for details.
pub mod extract {
    /// # An event from which additional data may be extracted
    ///
    /// The one notable thing about it is that it implements the [`EventInput`](`crate::EventInput`)
    /// trait. You probably won't need to access any of its fields directly.
    pub use falco_plugin_api::ss_plugin_event_input as EventInput;
    pub use falco_plugin_api::ss_plugin_field_extract_input as FieldExtractInput;

    pub use crate::plugin::extract::schema::field;
    pub use crate::plugin::extract::schema::{ExtractArgType, ExtractFieldInfo};
    pub use crate::plugin::extract::ExtractFieldRequestArg;
    pub use crate::plugin::extract::ExtractPlugin;
    pub use crate::plugin::storage::FieldStorage;
}

pub mod parse {
    pub use falco_plugin_api::ss_plugin_event_input as EventInput;
    pub use falco_plugin_api::ss_plugin_event_parse_input as ParseInput;

    pub use crate::plugin::parse::EventParseInput;
    pub use crate::plugin::parse::ParsePlugin;
}

pub mod async_event {
    pub use falco_event::events::PPME_ASYNCEVENT_E as AsyncEvent;

    pub use crate::plugin::async_event::async_handler::AsyncHandler;
    pub use crate::plugin::async_event::AsyncEventPlugin;
}

pub mod source {
    pub use crate::plugin::source::event_batch::EventBatch;
    pub use crate::plugin::source::open_params::{serialize_open_params, OpenParam};
    pub use crate::plugin::source::{ProgressInfo, SourcePlugin, SourcePluginInstance};
    pub use crate::strings::cstring_writer::CStringWriter;
    pub use falco_event::events::PPME_PLUGINEVENT_E as PluginEvent;
    pub use falco_plugin_api::ss_plugin_event_input as EventInput;
}

pub mod tables {
    pub use crate::plugin::exported_tables::DynamicField;
    pub use crate::plugin::exported_tables::DynamicFieldValue;
    pub use crate::plugin::exported_tables::DynamicTable;
    pub use crate::plugin::exported_tables::ExportedTable;
    pub use crate::plugin::tables::entry::TableEntry;
    pub use crate::plugin::tables::entry::TableEntryReader;
    pub use crate::plugin::tables::field::TypedTableField;
    pub use crate::plugin::tables::table::TypedTable;
    pub use crate::plugin::tables::table_reader::TableReader;
}

mod plugin;
mod strings;

#[doc(hidden)]
pub mod internals {
    pub mod base {
        pub use crate::plugin::base::wrappers;
    }

    pub mod source {
        pub use crate::plugin::source::wrappers;
    }

    pub mod extract {
        pub use crate::plugin::extract::wrappers;
    }

    pub mod parse {
        pub use crate::plugin::parse::wrappers;
    }

    pub mod async_events {
        pub use crate::plugin::async_event::wrappers;
    }
}
