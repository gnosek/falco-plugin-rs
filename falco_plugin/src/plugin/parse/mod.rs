use crate::plugin::base::Plugin;
use crate::plugin::tables::entry::TableEntry;
use crate::plugin::tables::key::TableKey;
use crate::plugin::tables::table::TypedTable;
use falco_event::EventType;
use falco_plugin_api::{ss_plugin_event_input, ss_plugin_event_parse_input};

#[doc(hidden)]
pub mod wrappers;

pub trait ParsePlugin: Plugin {
    const EVENT_TYPES: &'static [EventType];
    const EVENT_SOURCES: &'static [&'static str];

    fn parse_event(
        &mut self,
        event: &ss_plugin_event_input,
        parse_input: &ss_plugin_event_parse_input,
    ) -> anyhow::Result<()>;
}

pub trait EventParseInput {
    fn table_entry<K: TableKey>(&self, table: &TypedTable<K>, key: &K) -> Option<TableEntry>;
}

impl EventParseInput for ss_plugin_event_parse_input {
    fn table_entry<K: TableKey>(&self, table: &TypedTable<K>, key: &K) -> Option<TableEntry> {
        unsafe {
            Some(
                table
                    .get_entry(self.table_reader_ext.as_ref()?, key)?
                    .with_writer(self.table_writer_ext.as_ref()?),
            )
        }
    }
}
