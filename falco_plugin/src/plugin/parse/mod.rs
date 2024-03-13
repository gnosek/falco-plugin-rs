use falco_event::events::types::EventType;

use crate::parse::{EventInput, ParseInput};
use crate::plugin::base::Plugin;
use crate::plugin::tables::data::TableData;
use crate::plugin::tables::entry::TableEntry;
use crate::plugin::tables::table::TypedTable;

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
    /// - the plugin will only receive events of plugin type [`falco_event::events::PPME_PLUGINEVENT_E`].
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
/// See [`base::TableInitInput`](`crate::base::TableInitInput`) for details
pub trait EventParseInput {
    /// # Look up an entry in `table` corresponding to `key`
    ///
    /// See [`base::TableInitInput`](`crate::base::TableInitInput`) for details
    fn table_entry<K: TableData>(&self, table: &TypedTable<K>, key: &K) -> Option<TableEntry>;

    /// # Iterate over all entries in a table with mutable access
    ///
    /// The closure is called once for each table entry with a corresponding [`TableEntry`]
    /// object as a parameter.
    ///
    /// The iteration stops when either all entries have been processed or the closure returns `false`.
    fn iter_entries_mut<F, K>(&self, table: &TypedTable<K>, func: F) -> bool
    where
        F: FnMut(&mut TableEntry) -> bool,
        K: TableData;
}

impl EventParseInput for ParseInput {
    fn table_entry<K: TableData>(&self, table: &TypedTable<K>, key: &K) -> Option<TableEntry> {
        unsafe {
            Some(
                table
                    .get_entry(self.table_reader_ext.as_ref()?, key)?
                    .with_writer(self.table_writer_ext.as_ref()?),
            )
        }
    }

    fn iter_entries_mut<F, K>(&self, table: &TypedTable<K>, func: F) -> bool
    where
        F: FnMut(&mut TableEntry) -> bool,
        K: TableData,
    {
        unsafe {
            let Some(reader_vtable) = self.table_reader_ext.as_ref() else {
                return false;
            };
            let Some(writer_vtable) = self.table_writer_ext.as_ref() else {
                return false;
            };

            table.iter_entries_mut(reader_vtable, writer_vtable, func)
        }
    }
}
