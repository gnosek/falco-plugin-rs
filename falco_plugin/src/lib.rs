#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// reexport dependencies
pub use anyhow;
pub use falco_event as event;
pub use falco_plugin_api as api;
pub use schemars;
pub use serde;

/// Mark a struct type as a table value
///
/// Tables in Falco plugins are effectively maps from a key
/// to a (possibly dynamic) struct of values.
///
/// The default implementation for tables ([`tables::DynamicFieldValues`]) uses
/// dynamic fields only, but with this macro you can also define structs containing static
/// (predefined) fields that are accessible to your plugin without going through the Falco
/// plugin API.
///
/// A table can be fully static (no dynamic fields allowed). In this case, it must be tagged
/// with a `#[static_only]` attribute (to prevent accidental omission of the dynamic field values,
/// which would only get caught at runtime, possibly much later).
///
/// Alternatively, it can mark a single field as `#[dynamic]`. That field needs to implement
/// [`tables::TableValues`] and it will generally be of type [`tables::DynamicFieldValues`].
///
/// Fields tagged as `#[readonly]` won't be writable via the Falco API and fields tagged
/// as `#[hidden]` won't be exposed to the API at all. This is useful if you want to store data
/// that's incompatible with the Falco plugin API in your table.
///
/// # Example
/// ```
/// use std::ffi::CString;
/// use falco_plugin::tables::DynamicFieldValues;
/// use falco_plugin::TableValues;
///
/// #[derive(TableValues, Default)]     // all table structs must implement Default
/// #[static_only]                      // no dynamic fields in this one
/// struct TableWithStaticFieldsOnly {
///     #[readonly]
///     int_field: u64,                 // this field cannot be modified with the Falco API
///     string_field: CString,
///
///     #[hidden]
///     secret: Vec<u8>,                // this field is not visible via the Falco API
/// }
///
/// #[derive(TableValues, Default)]
/// struct AnotherTable {
///     #[readonly]
///     int_field: u64,                 // this field cannot be modified with the Falco API
///     string_field: CString,
///
///     #[hidden]
///     secret: Vec<u8>,                // this field is not visible via the Falco API
///
///     #[dynamic]
///     dynamic_fields: DynamicFieldValues, // dynamically added fields have their values here
/// }
/// ```
pub use falco_plugin_derive::TableValues;


pub use crate::plugin::error::FailureReason;

/// # The common foundation for all Falco plugins
///
/// All plugins must implement the [`base::Plugin`] trait which specifies some basic metadata
/// about the plugin. For example, a plugin that doesn't support any capabilities (which is
/// useless and would fail to load, but is a necessary step to building an actually useful plugin)
/// might look like:
///
/// ```
/// use std::ffi::CStr;
/// use falco_plugin::base::{Metric, Plugin};
/// use falco_plugin::plugin;
/// use falco_plugin::tables::TablesInput;
///
/// // define the type holding the plugin state
/// struct NoOpPlugin;
///
/// // implement the base::Plugin trait
/// impl Plugin for NoOpPlugin {
///     const NAME: &'static CStr = c"sample-plugin-rs";
///     const PLUGIN_VERSION: &'static CStr = c"0.0.1";
///     const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
///     const CONTACT: &'static CStr = c"you@example.com";
///     type ConfigType = ();
///
///     fn new(input: Option<&TablesInput>, config: Self::ConfigType)
///         -> Result<Self, anyhow::Error> {
///         Ok(NoOpPlugin)
///     }
///
///     fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
///         Ok(())
///     }
///
///     fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
///         []
///     }
/// }
///
/// // generate the actual plugin wrapper code
/// plugin!(NoOpPlugin);
/// ```
///
/// See the [`base::Plugin`] trait documentation for details.
pub mod base {
    pub use crate::plugin::base::metrics::{Metric, MetricLabel, MetricType, MetricValue};
    pub use crate::plugin::base::Plugin;
    pub use crate::plugin::schema::Json;
}

/// # Field extraction plugin support
///
/// Plugins with field extraction capability have the ability to extract information from events
/// based on fields. For example, a field (e.g. `proc.name`) extracts a value (e.g. process name
/// like `nginx`) from a syscall event. The plugin returns a set of supported fields, and there are
/// functions to extract a value given an event and field. The plugin framework can then build
/// filtering expressions (e.g. rule conditions) based on these fields combined with relational
/// and/or logical operators.
///
/// For example, given the expression `ct.name=root and ct.region=us-east-1`,
/// the plugin framework handles parsing the expression, calling the plugin to extract values for
/// fields `ct.name`/`ct.region` for a given event, and determining the result of the expression.
/// In a Falco output string like `An EC2 Node was created (name=%ct.name region=%ct.region)`,
/// the plugin framework handles parsing the output string, calling the plugin to extract values
/// for fields, and building the resolved string, replacing the template field names
/// (e.g. `%ct.region`) with values (e.g. `us-east-1`).
///
/// Plugins with this capability only focus on field extraction from events generated by other
/// plugins or by the core libraries. They do not provide an event source but can extract fields
/// from other event sources. The supported field extraction can be generic or be tied to a specific
/// event source. An example is JSON field extraction, where a plugin might be able to extract
/// fields from generic JSON payloads.
///
/// For your plugin to support field extraction, you will need to implement the [`extract::ExtractPlugin`]
/// trait and invoke the [`extract_plugin`] macro, for example:
///
/// ```
/// use std::ffi::{CStr, CString};
/// use anyhow::Error;
/// use falco_event::events::types::EventType;
/// use falco_plugin::base::{Metric, Plugin};
/// use falco_plugin::{extract_plugin, plugin};
/// use falco_plugin::extract::{
///     EventInput,
///     ExtractFieldInfo,
///     ExtractFieldRequestArg,
///     ExtractPlugin,
///     ExtractRequest,
///     field};
/// use falco_plugin::tables::{TableReader, TablesInput};
///
/// struct MyExtractPlugin;
/// impl Plugin for MyExtractPlugin {
///     // ...
/// #    const NAME: &'static CStr = c"sample-plugin-rs";
/// #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
/// #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
/// #    const CONTACT: &'static CStr = c"you@example.com";
/// #    type ConfigType = ();
/// #
/// #    fn new(input: Option<&TablesInput>, config: Self::ConfigType)
/// #        -> Result<Self, anyhow::Error> {
/// #        Ok(MyExtractPlugin)
/// #    }
/// #
/// #    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
/// #        Ok(())
/// #    }
/// #
/// #    fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
/// #        []
/// #    }
/// }
///
/// impl MyExtractPlugin { // note this is not the trait implementation
///     fn extract_sample(
///         &mut self,
///         _req: ExtractRequest<Self>,
///         _arg: ExtractFieldRequestArg,
///     ) -> Result<CString, Error> {
///         Ok(c"hello".to_owned())
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
    pub use crate::plugin::event::EventInput;
    pub use crate::plugin::extract::schema::field;
    pub use crate::plugin::extract::schema::{ExtractArgType, ExtractFieldInfo};
    pub use crate::plugin::extract::ExtractFieldRequestArg;
    pub use crate::plugin::extract::ExtractPlugin;
    pub use crate::plugin::extract::ExtractRequest;
    pub use crate::plugin::storage::FieldStorage;
}

/// # Event parsing support
///
/// Plugins with event parsing capability can hook into an event stream and receive all of its events
/// sequentially. The parsing phase is the stage in the event processing loop in which
/// the Falcosecurity libraries inspect the content of the events' payload and use it to apply
/// internal state updates or implement additional logic. This phase happens before any field
/// extraction for a given event. Each event in a given stream is guaranteed to be received at most once.
///
/// For your plugin to support event parsing, you will need to implement the [`parse::ParsePlugin`]
/// trait and invoke the [`parse_plugin`] macro, for example:
///
/// ```
/// use std::ffi::{CStr, CString};
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicBool, Ordering};
/// use std::thread::JoinHandle;
/// use anyhow::Error;
/// use falco_event::{ };
/// use falco_event::events::types::EventType;
/// use falco_plugin::base::{Metric, Plugin};
/// use falco_plugin::{parse_plugin, plugin};
/// use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
/// use falco_plugin::tables::TablesInput;
/// use falco_plugin_api::{ss_plugin_event_input, ss_plugin_event_parse_input};
///
/// struct MyParsePlugin;
///
/// impl Plugin for MyParsePlugin {
///     // ...
/// #    const NAME: &'static CStr = c"sample-plugin-rs";
/// #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
/// #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
/// #    const CONTACT: &'static CStr = c"you@example.com";
/// #    type ConfigType = ();
/// #
/// #    fn new(input: Option<&TablesInput>, config: Self::ConfigType)
/// #        -> Result<Self, anyhow::Error> {
/// #        Ok(MyParsePlugin)
/// #    }
/// }
///
/// impl ParsePlugin for MyParsePlugin {
///     const EVENT_TYPES: &'static [EventType] = &[]; // inspect all events...
///     const EVENT_SOURCES: &'static [&'static str] = &[]; // ... from all event sources
///
///     fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput)
///         -> anyhow::Result<()> {
///         let event = event.event()?;
///         let event = event.load_any()?;
///
///         // any processing you want here, e.g. involving tables
///
///         Ok(())
///     }
/// }
///
/// plugin!(MyParsePlugin);
/// parse_plugin!(MyParsePlugin);
/// ```
pub mod parse {
    pub use crate::plugin::event::EventInput;
    pub use crate::plugin::parse::ParseInput;
    pub use crate::plugin::parse::ParsePlugin;
}

/// # Asynchronous event support
///
/// Plugins with async events capability can enrich an event stream from a given source (not
/// necessarily implemented by itself) by injecting events asynchronously in the stream. Such
/// a feature can be used for implementing notification systems or recording state transitions
/// in the event-driven model of the Falcosecurity libraries, so that they can be available to other
/// components at runtime or when the event stream is replayed through a capture file.
///
/// For example, the Falcosecurity libraries leverage this feature internally to implement metadata
/// enrichment systems such as the one related to container runtimes. In that case, the libraries
/// implement asynchronous jobs responsible for retrieving such information externally outside
/// the main event processing loop so that it's non-blocking. The worker jobs produce a notification
/// event every time a new container is detected and inject it asynchronously in the system event
/// stream to be later processed for state updates and for evaluating Falco rules.
///
/// For your plugin to support asynchronous events, you will need to implement the [`async_event::AsyncEventPlugin`]
/// trait and invoke the [`async_event`] macro, for example:
///
/// ```
/// use std::ffi::{CStr, CString};
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicBool, Ordering};
/// use std::thread::JoinHandle;
/// use anyhow::Error;
/// use falco_event::events::Event;
/// use falco_event::events::EventMetadata;
/// use falco_plugin::base::{Metric, Plugin};
/// use falco_plugin::{async_event_plugin, plugin};
/// use falco_plugin::async_event::{AsyncEvent, AsyncEventPlugin, AsyncHandler};///
/// use falco_plugin::tables::TablesInput;
///
/// struct MyAsyncPlugin {
///     stop_request: Arc<AtomicBool>,
///     thread: Option<JoinHandle<Result<(), Error>>>,
/// }
///
/// impl Plugin for MyAsyncPlugin {
///     // ...
/// #    const NAME: &'static CStr = c"sample-plugin-rs";
/// #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
/// #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
/// #    const CONTACT: &'static CStr = c"you@example.com";
/// #    type ConfigType = ();
/// #
/// #    fn new(input: Option<&TablesInput>, config: Self::ConfigType)
/// #        -> Result<Self, anyhow::Error> {
/// #        Ok(MyAsyncPlugin {
/// #            stop_request: Arc::new(Default::default()),
/// #            thread: None,
/// #        })
/// #    }
/// }
///
/// impl AsyncEventPlugin for MyAsyncPlugin {
///     const ASYNC_EVENTS: &'static [&'static str] = &[]; // generate any async events
///     const EVENT_SOURCES: &'static [&'static str] = &[]; // attach to all event sources
///
///     fn start_async(&mut self, handler: AsyncHandler) -> Result<(), Error> {
///         // stop the thread if it was already running
///         if self.thread.is_some() {
///            self.stop_async()?;
///         }
///
///         // start a new thread
///         self.stop_request.store(false, Ordering::Relaxed);
///         let stop_request = Arc::clone(&self.stop_request);
///         self.thread = Some(std::thread::spawn(move || {
///             // check the stop flag periodically: we must stop the thread
///             // when requested
///             while !stop_request.load(Ordering::Relaxed) {
///                 // build an event
///                 let event = AsyncEvent {
///                     plugin_id: Some(0),
///                     name: Some(c"sample_async"),
///                     data: Some(b"hello"),
///                 };
///
///                 let metadata = EventMetadata::default();
///
///                 let event = Event {
///                     metadata,
///                     params: event,
///                 };
///
///                 // submit it to the main event loop
///                 handler.emit(event)?;
///             }
///             Ok(())
///         }));
///         Ok(())
///     }
///
///     fn stop_async(&mut self) -> Result<(), Error> {
///         self.stop_request.store(true, Ordering::Relaxed);
///         let Some(handle) = self.thread.take() else {
///             return Ok(());
///         };
///
///         match handle.join() {
///             Ok(res) => res,
///             Err(e) => std::panic::resume_unwind(e),
///         }
///     }
/// }
///
/// plugin!(MyAsyncPlugin);
/// async_event_plugin!(MyAsyncPlugin);
/// ```
pub mod async_event {
    pub use falco_event::events::types::PPME_ASYNCEVENT_E as AsyncEvent;

    pub use crate::plugin::async_event::async_handler::AsyncHandler;
    pub use crate::plugin::async_event::AsyncEventPlugin;
}

/// # Event sourcing support
///
/// Plugins with event sourcing capability provide a new event source and make it available to
/// libscap and libsinsp. They have the ability to "open" and "close" a stream of events and return
/// those events to the plugin framework. They also provide a plugin ID, which is globally unique
/// and is used in capture files. Event sources provided by plugins with this capability are tied
/// to the events they generate and can be used by [plugins with field extraction](crate::source)
/// capabilities and within Falco rules.
/// For your plugin to support event sourcing, you will need to implement the [`source::SourcePlugin`]
/// trait and invoke the [`source_plugin`] macro, for example:
///
/// ```
/// use std::ffi::{CStr, CString};
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicBool, Ordering};
/// use std::thread::JoinHandle;
/// use anyhow::Error;
/// use falco_event::events::Event;
/// use falco_plugin::base::{Metric, Plugin};
/// use falco_plugin::{plugin, source_plugin};
/// use falco_plugin::source::{
///     EventBatch,
///     EventInput,
///     PluginEvent,
///     SourcePlugin,
///     SourcePluginInstance};
/// use falco_plugin::tables::TablesInput;
/// use falco_plugin_api::ss_plugin_event_input;
///
/// struct MySourcePlugin;
///
/// impl Plugin for MySourcePlugin {
///     // ...
/// #    const NAME: &'static CStr = c"sample-plugin-rs";
/// #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
/// #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
/// #    const CONTACT: &'static CStr = c"you@example.com";
/// #    type ConfigType = ();
/// #
/// #    fn new(input: Option<&TablesInput>, config: Self::ConfigType)
/// #        -> Result<Self, anyhow::Error> {
/// #        Ok(MySourcePlugin)
/// #    }
/// #
/// #    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
/// #        Ok(())
/// #    }
/// #
/// #    fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
/// #        []
/// #    }
/// }
///
/// struct MySourcePluginInstance;
///
/// impl SourcePlugin for MySourcePlugin {
///     type Instance = MySourcePluginInstance;
///     const EVENT_SOURCE: &'static CStr = c"my-source-plugin";
///     const PLUGIN_ID: u32 = 0; // we do not have one assigned for this example :)
///
///     fn open(&mut self, params: Option<&str>) -> Result<Self::Instance, Error> {
///         // we do not use the open parameters in this example
///         Ok((MySourcePluginInstance))
///     }
///
///     fn event_to_string(&mut self, event: &EventInput) -> Result<CString, Error> {
///         // a string representation for our event; just copy out the whole event data
///         // (it's an ASCII string); please note we need the copy because we need to add
///         // a NUL terminator to convert the byte buffer to a C string
///
///         // get the raw event
///         let event = event.event()?;
///         // parse the fields into a PluginEvent
///         let plugin_event = event.load::<PluginEvent>()?;
///
///         // take a copy of the event data (it's in an Option because we never know if events
///         // have all the fields, and it's important to handle short events for backwards
///         // compatibility).
///         let data = plugin_event.params.event_data.map(|e| e.to_vec()).unwrap_or_default();
///
///         // convert the data to a CString and return it
///         Ok(CString::new(data)?)
///     }
/// }
///
/// impl SourcePluginInstance for MySourcePluginInstance {
///     type Plugin = MySourcePlugin;
///
///     fn next_batch(&mut self, plugin: &mut Self::Plugin, batch: &mut EventBatch)
///     -> Result<(), Error> {
///         let event = Self::plugin_event(b"hello, world");
///         batch.add(event)?;
///
///         Ok(())
///     }}
///
/// plugin!(MySourcePlugin);
/// source_plugin!(MySourcePlugin);
/// ```
pub mod source {
    pub use crate::plugin::event::EventInput;
    pub use crate::plugin::source::event_batch::EventBatch;
    pub use crate::plugin::source::open_params::{serialize_open_params, OpenParam};
    pub use crate::plugin::source::{ProgressInfo, SourcePlugin, SourcePluginInstance};
    pub use crate::strings::cstring_writer::CStringWriter;
    pub use falco_event::events::types::PPME_PLUGINEVENT_E as PluginEvent;
}

/// # Creating and accessing tables
///
/// Tables are a mechanism to share data between plugins (and Falco core).
pub mod tables {
    pub use crate::plugin::exported_tables::DynamicField;
    pub use crate::plugin::exported_tables::DynamicFieldValue;
    pub use crate::plugin::exported_tables::DynamicFieldValues;
    pub use crate::plugin::exported_tables::DynamicTable;
    pub use crate::plugin::exported_tables::ExportedTable;
    pub use crate::plugin::exported_tables::FieldValue;
    pub use crate::plugin::exported_tables::StaticField;
    pub use crate::plugin::exported_tables::TableValues;
    pub use crate::plugin::tables::data::Bool;
    pub use crate::plugin::tables::data::FieldTypeId;
    pub use crate::plugin::tables::data::TableData;
    pub use crate::plugin::tables::field::Field;
    pub use crate::plugin::tables::table::Table;
    pub use crate::plugin::tables::vtable::TableReader;
    pub use crate::plugin::tables::vtable::TableWriter;
    pub use crate::plugin::tables::vtable::TablesInput;
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

    pub mod tables {
        pub mod export {
            pub use crate::plugin::exported_tables::StaticField;
        }
    }
}
