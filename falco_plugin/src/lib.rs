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
/// The default implementation for tables ([`tables::export::DynamicFieldValues`]) uses
/// dynamic fields only, but with this macro you can also define structs containing static
/// (predefined) fields that are accessible to your plugin without going through the Falco
/// plugin API.
///
/// A table can be fully static (no dynamic fields allowed). In this case, it must be tagged
/// with a `#[static_only]` attribute (to prevent accidental omission of the dynamic field values,
/// which would only get caught at runtime, possibly much later).
///
/// Alternatively, it can mark a single field as `#[dynamic]`. That field needs to implement
/// [`plugin::exported_tables::entry::traits::Entry`] and it will generally be of type [`plugin::exported_tables::entry::dynamic::DynamicFieldValues`].
///
/// Fields tagged as `#[readonly]` won't be writable via the Falco API and fields tagged
/// as `#[hidden]` won't be exposed to the API at all. This is useful if you want to store data
/// that's incompatible with the Falco plugin API in your table.
///
/// # Example
/// ```
/// use std::ffi::CString;
/// use falco_plugin::tables::export::DynamicFieldValues;
/// use falco_plugin::Entry;
///
/// #[derive(Entry, Default)]     // all table structs must implement Default
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
/// #[derive(Entry, Default)]
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
pub use falco_plugin_derive::Entry;


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
/// Tables are a mechanism to share data between plugins (and Falco core). There are three major
/// concepts that relate to working with Falco plugin tables:
/// - a table is a collection of entries, each under a different key, like a hash map or a SQL
///   table with a single primary key
/// - an entry is a struct containing the actual values (corresponding to an entry in the hash map
///   or a row in the SQL table)
/// - a field is a descriptor for a particular item in an entry. It does not have an equivalent
///   in the hash map analogy, but corresponds to a column in the SQL table. In particular, a field
///   is not attached to any particular entry.
///
/// ## Example (in pseudocode)
///
/// Consider a table called `threads` that has two fields:
/// ```ignore
/// struct Thread {
///     uid: u64,
///     comm: CString,
/// }
/// ```
///
/// and uses the thread id (`tid: u64`) as the key. To read the `comm` of the thread with tid 1,
/// you would need the following operations:
///
/// ```ignore
/// // get the table (at initialization time)
/// let threads_table = get_table("threads");
///
/// // get the field (at initialization time)
/// let comm_field = threads_table.get_field("comm");
///
/// // get an entry in the table (during parsing or extraction)
/// let tid1_entry = threads_table.get_entry(1);
///
/// // get the field value from an entry
/// let comm = tid1_entry.get_field_value(comm_field);
/// ```
///
/// The Rust SDK tries to hide this and expose a more struct-oriented approach, though you can
/// access fields in entries manually if you want (e.g. if you only know the field name at runtime).
///
/// # Supported field types
///
/// The following types can be used in fields visible over the plugin API:
/// - integer types (u8/i8, u16/i16, u32/i32, u64/i64)
/// - the bool type
/// - CString
///
/// Any other types are not supported, including in particular e.g. collections (`Vec<T>`),
/// enums or any structs.
///
/// Using tables as fields (nested tables) is currently very experimental and doesn't really
/// work yet.
///
/// # Exporting and importing tables
///
/// Tables can be exported (exposed to other plugins) using the [`tables::export`] module.
///
/// Existing tables (from other plugins) can be imported using the [`tables::import`] module.
///
/// See the corresponding modules' documentation for details.
///
/// # Access control
///
/// Not all plugins are created equal when it comes to accessing tables. Only
/// [parse plugins](`crate::parse::ParsePlugin`) and [extract plugins](`crate::extract::ExtractPlugin`)
/// can access tables. Moreover, during field extraction you can only read tables, not write them.
/// To summarize:
///
/// | Plugin type | Initialization phase | Action phase ^1 |
/// |-------------|----------------------|-----------------|
/// | source      | no access            | no access       |
/// | parse       | full access          | read/write      |
/// | extract     | full access ^2       | read only       |
/// | async       | no access            | no access       |
///
/// **Notes**:
/// 1. "Action phase" is anything that happens after [`crate::base::Plugin::new`] returns, i.e.
///    event generation, parsing/extraction or any background activity (in async plugins).
///
/// 2. Even though you can create tables and fields during initialization of an extract plugin,
///    there's no way to modify them later (create table entries or write to fields), so it's
///    more useful to constrain yourself to looking up existing tables/fields.
///
/// ## Access control implementation
///
/// Access control is implemented by requiring a particular object to actually perform table
/// operations:
/// - [`tables::TablesInput`] to manage (look up/create) tables and fields
/// - [`tables::TableReader`] to look up table entries and get field values
/// - [`tables::TableWriter`] to create entries and write field values
///
/// These get passed to your plugin whenever a particular class of operations is allowed.
/// Note that [`crate::base::Plugin::new`] receives an `Option<&TablesInput>` and the option
/// is populated only for parsing and extraction plugins (source and async plugins receive `None`).
///
/// # The flow of using tables
///
/// The access controls described above push you into structuring your plugins in a specific way.
/// You cannot e.g. define tables in a source plugin, which is good, since that would break
/// when reading capture files (the source plugin is not involved in that case). To provide
/// a full-featured plugin that generates events, maintains some state and exposes it via
/// extracted fields, you need separate capabilities (that may live in a single plugin or be
/// spread across different ones):
/// - a source plugin *only* generates events
/// - a parse plugin creates the state tables and updates them during event parsing
/// - an extract plugin reads the tables and returns field values
///
/// # Dynamic fields
///
/// Tables can have fields added to them at runtime, from other plugins than the one that
/// created them (you can add dynamic fields to tables you created too, but that makes little sense).
///
/// These fields behave just like fields defined statically in the table and can be used by plugins
/// loaded after the current one. This can be used to e.g. add some data to an existing table
/// in a parse plugin and expose it in an extract plugin.
pub mod tables {
    pub use crate::plugin::tables::vtable::TableReader;
    pub use crate::plugin::tables::vtable::TableWriter;
    pub use crate::plugin::tables::vtable::TablesInput;

    /// Exporting tables to other plugins
    ///
    /// Exporting a table to other plugins is done using the [`crate::Entry`] derive macro.
    /// It lets you use a struct type as a parameter to [`export::DynamicTable`]. You can then create
    /// a new table using [`TablesInput::add_table`].
    ///
    /// # Example
    ///
    /// ```
    /// use std::ffi::{CStr, CString};
    /// use falco_plugin::base::Plugin;
    /// use falco_plugin::tables::TablesInput;
    /// use falco_plugin::tables::export;
    /// use falco_plugin::Entry;
    ///
    /// // define the struct representing each table entry
    /// #[derive(Entry, Default)]
    /// struct ExportedTable {
    ///     #[readonly]
    ///     int_field: u64,        // do not allow writes via the plugin API
    ///     string_field: CString, // allow writes via the plugin API
    ///     #[hidden]
    ///     secret: Vec<u8>,       // do not expose over the plugin API at all
    ///
    ///     #[dynamic]
    ///     dynamic: export::DynamicFieldValues,
    /// }
    ///
    /// // define the type holding the plugin state
    /// struct MyPlugin {
    ///     // you can use methods on this instance to access fields bypassing the Falco table API
    ///     // (for performance within your own plugin)
    ///     exported_table: &'static mut export::DynamicTable<u64, ExportedTable>,
    /// }
    ///
    /// // implement the base::Plugin trait
    /// impl Plugin for MyPlugin {
    ///     // ...
    ///#     const NAME: &'static CStr = c"sample-plugin-rs";
    ///#     const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    ///#     const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
    ///#     const CONTACT: &'static CStr = c"you@example.com";
    ///#     type ConfigType = ();
    ///
    ///     fn new(input: Option<&TablesInput>, config: Self::ConfigType)
    ///         -> Result<Self, anyhow::Error> {
    ///
    ///         let Some(input) = input else {
    ///             anyhow::bail!("Did not get tables input");
    ///         };
    ///
    ///         // create a new table called "exported"
    ///         //
    ///         // The concrete type is inferred from the field type the result is stored in.
    ///         let exported_table = input.add_table(export::DynamicTable::new(c"exported"))?;
    ///
    ///         Ok(MyPlugin { exported_table })
    ///     }
    /// }
    /// ```
    pub mod export {
        pub use crate::plugin::exported_tables::entry::dynamic::DynamicFieldValues;
        pub use crate::plugin::exported_tables::field_descriptor::DynamicField;
        pub use crate::plugin::exported_tables::field_value::traits::FieldValue;
        pub use crate::plugin::exported_tables::table::DynamicTable;
    }

    /// # Importing tables from other plugins (or Falco core)
    ///
    /// Your plugin can access tables exported by other plugins (or Falco core) by importing them.
    /// The recommended approach is to use the `#[derive(TableMetadata)]` macro for that purpose.
    ///
    /// You will probably want to define two additional type aliases, so that the full definition
    /// involves:
    /// - a type alias for the whole table
    /// - a type alias for a single table entry
    /// - a metadata struct, describing an entry (somewhat indirectly)
    ///
    /// For example:
    ///
    /// ```
    /// # use std::ffi::CStr;
    /// # use std::rc::Rc;
    /// # use falco_plugin::tables::import::{Entry, Field, Table, TableMetadata};
    /// #
    /// type ImportedThing = Entry<Rc<ImportedThingMetadata>>;
    /// type ImportedThingTable = Table<u64, ImportedThing>;
    ///
    /// #[derive(TableMetadata)]
    /// #[entry_type(ImportedThing)]
    /// struct ImportedThingMetadata {
    ///     imported: Field<u64, ImportedThing>,
    ///
    ///     #[name(c"type")]
    ///     thing_type: Field<u64, ImportedThing>,
    ///
    ///     #[custom]
    ///     added: Field<CStr, ImportedThing>,
    /// }
    ///
    /// # // make this doctest a module, not a function: https://github.com/rust-lang/rust/issues/83583#issuecomment-1083300448
    /// # fn main() {}
    /// ```
    ///
    /// In contrast to [exported tables](`crate::tables::export`), the entry struct does not
    /// contain any accessible fields. It only provides generated methods to access each field
    /// using the plugin API. This means that each read/write is fairly expensive (involves
    /// method calls), so you should probably cache the values in local variables.
    ///
    /// ## Declaring fields
    ///
    /// You need to declare each field you're going to use in a particular table, by providing
    /// a corresponding [`import::Field`] field in the metadata struct. You do **not** need
    /// to declare all fields in the table, or put the fields in any particular order, but you
    /// **do** need to get the type right (otherwise you'll get an error at initialization time).
    ///
    /// The Falco table field name is the same as the field name in your metadata struct,
    /// unless overridden by `#[name(c"foo")]`. This is useful if a field's name is a Rust reserved
    /// word (e.g. `type`).
    ///
    /// You can also add fields to imported tables. To do that, tag the field with a `#[custom]`
    /// attribute. It will be then added to the table instead of looking it up in existing fields.
    /// Note that multiple plugins can add a field with the same name and type, which will make them
    /// all use the same field (they will share the data). Adding a field multiple times
    /// with different types is not allowed and will cause an error at initialization time.
    ///
    /// ## Generated methods
    ///
    /// Each scalar field gets a getter and setter method, e.g. declaring a metadata struct like
    /// the above example will generate the following methods **on the `ImportedThing` type**:
    /// ```ignore
    /// fn get_imported(&self, reader: &TableReader) -> Result<u64, anyhow::Error>;
    /// fn set_imported(&self, writer: &TableWriter, value: &u64) -> Result<(), anyhow::Error>;
    ///
    /// fn get_thing_type(&self, reader: &TableReader) -> Result<u64, anyhow::Error>;
    /// fn set_thing_type(&self, writer: &TableWriter, value: &u64) -> Result<(), anyhow::Error>;
    ///
    /// fn get_added<'a>(&'a self, reader: &TableReader) -> Result<&'a CStr, anyhow::Error>;
    /// fn set_added(&self, writer: &TableWriter, value: &CStr) -> Result<(), anyhow::Error>;
    /// ```
    ///
    /// **Note**: setters do not take `&mut self` as all the mutation happens on the other side
    /// of the API (presumably in another plugin).
    ///
    /// **Note**: non-scalar fields are limited to nested tables, which are disabled for now
    /// (due to issues within the plugin API itself), so the description above applies to all types.
    ///
    /// # Example
    ///
    /// ```
    /// use std::ffi::CStr;
    /// use std::rc::Rc;
    /// use falco_plugin::anyhow::Error;
    /// use falco_plugin::base::Plugin;
    /// use falco_plugin::event::events::types::EventType;
    /// use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
    /// use falco_plugin::tables::TablesInput;
    /// use falco_plugin::tables::import::{Entry, Field, Table, TableMetadata};
    ///
    /// #[derive(TableMetadata)]
    /// #[entry_type(ImportedThing)]
    /// struct ImportedThingMetadata {
    ///     imported: Field<u64, ImportedThing>,
    ///
    ///     #[name(c"type")]
    ///     thing_type: Field<u64, ImportedThing>,
    ///
    ///     #[custom]
    ///     added: Field<CStr, ImportedThing>,
    /// }
    ///
    /// type ImportedThing = Entry<Rc<ImportedThingMetadata>>;
    /// type ImportedThingTable = Table<u64, ImportedThing>;
    ///
    /// struct MyPlugin {
    ///     things: ImportedThingTable,
    /// }
    ///
    /// impl Plugin for MyPlugin {
    ///     // ...
    ///#     const NAME: &'static CStr = c"dummy_extract";
    ///#     const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    ///#     const DESCRIPTION: &'static CStr = c"test plugin";
    ///#     const CONTACT: &'static CStr = c"rust@localdomain.pl";
    ///#     type ConfigType = ();
    ///
    ///     fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
    ///         let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;
    ///         let things: ImportedThingTable = input.get_table(c"things")?;
    ///
    ///         Ok(Self { things })
    ///     }
    /// }
    ///
    /// impl ParsePlugin for MyPlugin {
    ///     const EVENT_TYPES: &'static [EventType] = &[];
    ///     const EVENT_SOURCES: &'static [&'static str] = &[];
    ///
    ///     fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput)
    ///         -> anyhow::Result<()> {
    ///         // creating and accessing entries
    ///
    ///         // create a new entry (not yet attached to a table key)
    ///         let entry = self.things.create_entry(&parse_input.writer)?;
    ///         entry.set_imported(&parse_input.writer, &5u64)?;
    ///
    ///         // attach the entry to a table key
    ///         self.things.insert(&parse_input.writer, &1u64, entry)?;
    ///
    ///         // look up the entry we have just added
    ///         let entry = self.things.get_entry(&parse_input.reader, &1u64)?;
    ///         assert_eq!(entry.get_imported(&parse_input.reader).ok(), Some(5u64));
    ///
    ///         Ok(())
    ///     }
    /// }
    ///
    /// # // make this doctest a module, not a function: https://github.com/rust-lang/rust/issues/83583#issuecomment-1083300448
    /// # fn main() {}
    /// ```
    ///
    /// **Note**: The derive macro involves creating a private module (to avoid polluting
    /// the top-level namespace with a bunch of one-off traits), so you cannot use it inside
    /// a function due to scoping issues. See <https://github.com/rust-lang/rust/issues/83583>
    /// for details.
    ///
    /// # Bypassing the derive macro
    ///
    /// The derive macro boils down to automatically calling get_field/add_field for each
    /// field defined in the metadata struct (and generating getters/setters). If you don't know
    /// the field names in advance (e.g. when supporting different versions of "parent" plugins),
    /// there is the [`import::RuntimeEntry`] type alias, which makes you responsible for holding
    /// the field structs (probably in your plugin type) and requires you to use the generic
    /// read_field/write_field methods, in exchange for the flexibility.
    ///
    /// The above example can be rewritten without the derive macro as follows:
    ///
    /// ```
    /// use std::ffi::CStr;
    /// use std::rc::Rc;
    /// use falco_plugin::anyhow::Error;
    /// use falco_plugin::base::Plugin;
    /// use falco_plugin::event::events::types::EventType;
    /// use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
    /// use falco_plugin::tables::TablesInput;
    /// use falco_plugin::tables::import::{Field, RuntimeEntry, Table};
    ///
    /// struct ImportedThingTag;
    /// type ImportedThing = RuntimeEntry<ImportedThingTag>;
    /// type ImportedThingTable = Table<u64, ImportedThing>;
    ///
    /// struct MyPlugin {
    ///     things: ImportedThingTable,
    ///     thing_imported_field: Field<u64, ImportedThing>,
    ///     thing_type_field: Field<u64, ImportedThing>,
    ///     thing_added_field: Field<CStr, ImportedThing>,
    /// }
    ///
    /// impl Plugin for MyPlugin {
    ///     // ...
    ///#     const NAME: &'static CStr = c"dummy_extract";
    ///#     const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    ///#     const DESCRIPTION: &'static CStr = c"test plugin";
    ///#     const CONTACT: &'static CStr = c"rust@localdomain.pl";
    ///#     type ConfigType = ();
    ///
    ///     fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
    ///         let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;
    ///         let things: ImportedThingTable = input.get_table(c"things")?;
    ///         let thing_imported_field = things.get_field(input, c"imported")?;
    ///         let thing_type_field = things.get_field(input, c"type")?;
    ///         let thing_added_field = things.add_field(input, c"added")?;
    ///
    ///         Ok(Self {
    ///             things,
    ///             thing_imported_field,
    ///             thing_type_field,
    ///             thing_added_field,
    ///         })
    ///     }
    /// }
    ///
    /// impl ParsePlugin for MyPlugin {
    ///     const EVENT_TYPES: &'static [EventType] = &[];
    ///     const EVENT_SOURCES: &'static [&'static str] = &[];
    ///
    ///     fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput)
    ///         -> anyhow::Result<()> {
    ///         // creating and accessing entries
    ///
    ///         // create a new entry (not yet attached to a table key)
    ///         let entry = self.things.create_entry(&parse_input.writer)?;
    ///         entry.write_field(&parse_input.writer, &self.thing_imported_field, &5u64)?;
    ///
    ///         // attach the entry to a table key
    ///         self.things.insert(&parse_input.writer, &1u64, entry)?;
    ///
    ///         // look up the entry we have just added
    ///         let entry = self.things.get_entry(&parse_input.reader, &1u64)?;
    ///         assert_eq!(
    ///             entry.read_field(&parse_input.reader, &self.thing_imported_field).ok(),
    ///             Some(5u64),
    ///         );
    ///
    ///         Ok(())
    ///     }
    /// }
    /// ```
    ///
    /// **Note**: in the above example, `ImportedThingTag` is just an empty struct, used to
    /// distinguish entries (and fields) from different types between one another. You can
    /// skip this and do not pass the second generic argument to `Field` and `Table`
    /// (it will default to `RuntimeEntry<()>`), but you lose compile time validation for
    /// accessing fields from the wrong table. It will still be caught at runtime.
    ///
    /// See the [`import::Table`] type for additional methods on tables, to e.g. iterate
    /// over entries or clear the whole table.
    pub mod import {
        pub use crate::plugin::tables::data::Bool;
        pub use crate::plugin::tables::data::TableData;
        pub use crate::plugin::tables::field::Field;
        pub use crate::plugin::tables::runtime::RuntimeEntry;
        pub use crate::plugin::tables::table::Table;
        pub use crate::plugin::tables::Entry;

        /// Mark a struct type as an imported table entry metadata
        ///
        /// See the [module documentation](`crate::tables::import`) for details.
        pub use falco_plugin_derive::TableMetadata;
    }
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
        pub use crate::plugin::tables::data::FieldTypeId;

        pub use crate::plugin::tables::data::Key;
        pub use crate::plugin::tables::data::Value;
        pub use crate::plugin::tables::traits::Entry;
        pub use crate::plugin::tables::traits::EntryWrite;
        pub use crate::plugin::tables::traits::RawFieldValueType;
        pub use crate::plugin::tables::traits::TableAccess;
        pub use crate::plugin::tables::traits::TableMetadata;
        pub use crate::plugin::tables::RawTable;

        pub mod export {
            pub use crate::plugin::exported_tables::entry::traits::Entry;
            pub use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
            pub use crate::plugin::exported_tables::field_value::traits::FieldValue;
            pub use crate::plugin::exported_tables::field_value::traits::StaticField;
            pub use crate::plugin::tables::data::FieldTypeId;
        }
    }
}
