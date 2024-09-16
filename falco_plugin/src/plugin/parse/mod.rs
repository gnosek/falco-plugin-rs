use crate::parse::{EventInput, ParseInput};
use crate::plugin::base::Plugin;
use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::vtable::TableReader;
use crate::tables::TableWriter;
use falco_event::events::types::EventType;

#[doc(hidden)]
pub mod wrappers;

/// # Support for event parse plugins
pub trait ParsePlugin: Plugin {
    /// # Supported event types
    ///
    /// This list contains the event types that this plugin will receive
    /// for event parsing. Events that are not included in this list
    /// will not be received by the plugin.
    ///
    /// This is a non-functional filter that should not influence the plugin's
    /// functional behavior. Instead, this is a performance optimization
    /// with the goal of avoiding unnecessary communication between the
    /// framework and the plugin for events that are known to be not used for
    /// event parsing.
    ///
    /// If this list is empty, then:
    /// - the plugin will receive every event type if [`ParsePlugin::EVENT_SOURCES`]
    ///   is compatible with the "syscall" event source, otherwise
    /// - the plugin will only receive events of plugin type [`source::PluginEvent`](`crate::source::PluginEvent`)
    const EVENT_TYPES: &'static [EventType];

    /// # Supported event sources
    ///
    /// This list contains the event sources that this plugin is capable of parsing.
    ///
    /// If this list is empty, then if plugin has sourcing capability, and implements a specific
    /// event source, it will only receive events matching its event source, otherwise it will
    /// receive events from all event sources.
    const EVENT_SOURCES: &'static [&'static str];

    /// # Parse an event
    ///
    /// Receives an event from the current capture and parses its content.
    /// The plugin is guaranteed to receive an event at most once, after any
    /// operation related the event sourcing capability, and before
    /// any operation related to the field extraction capability.
    fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()>;
}

/// # Allow table access during event parsing
///
/// See [`crate::tables::TablesInput`] for details
pub trait EventParseInput {
    /// # Build a TableReader from the parse input
    fn table_reader(&self) -> Option<TableReader>;

    /// # Build a TableWriter from the parse input
    fn table_writer(&self) -> Option<TableWriter>;
}

impl EventParseInput for ParseInput {
    fn table_reader(&self) -> Option<TableReader> {
        unsafe {
            let last_error = LastError::new(self.owner, self.get_owner_last_error?);
            TableReader::try_from(self.table_reader_ext.as_ref()?, last_error).ok()
        }
    }

    fn table_writer(&self) -> Option<TableWriter> {
        unsafe {
            let last_error = LastError::new(self.owner, self.get_owner_last_error?);
            TableWriter::try_from(self.table_writer_ext.as_ref()?, last_error).ok()
        }
    }
}
