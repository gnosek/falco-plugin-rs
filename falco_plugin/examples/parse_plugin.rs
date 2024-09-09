use std::ffi::{CStr, CString};

use falco_event::events::types::EventType;
use falco_plugin::base::Plugin;
use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
use falco_plugin::tables::export::{Entry, Private, Public, Readonly, Table};
use falco_plugin::tables::import::Field;
use falco_plugin::tables::import::{RuntimeEntry, Table as ImportedTable};
use falco_plugin::tables::TablesInput;
use falco_plugin::{parse_plugin, plugin};

#[derive(Entry)]
struct AnotherTable {
    int_field: Readonly<u64>,
    string_field: Public<CString>,
    secret: Private<Vec<u8>>,
}

#[derive(Entry)]
struct Nested {
    bool_field: Public<bool>,
}

#[derive(Entry)]
struct TableWithNestedSubtable {
    int_field: Readonly<u64>,
    string_field: Public<CString>,
    nested: Box<Table<u64, Nested>>,

    #[allow(dead_code)]
    secret: Private<Vec<u8>>,
}

struct ThreadTable;

pub struct DummyPlugin {
    thread_table: ImportedTable<i64, RuntimeEntry<ThreadTable>>,
    sample_field: Field<u64, RuntimeEntry<ThreadTable>>,
    #[allow(dead_code)]
    another_table: Box<Table<u64, AnotherTable>>,
    table_with_static_fields_only: Box<Table<u64, TableWithNestedSubtable>>,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"parse-plugin-rs";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"sample source plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, anyhow::Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get tables input"))?;

        let thread_table: ImportedTable<i64, RuntimeEntry<ThreadTable>> =
            input.get_table(c"threads")?;
        let sample_field = thread_table.add_field::<u64>(input, c"sample")?;

        let another_table = input.add_table(Table::new(c"another")?)?;
        let table_with_static_fields_only = input.add_table(Table::new(c"static_fields_only")?)?;

        Ok(DummyPlugin {
            thread_table,
            sample_field,
            another_table,
            table_with_static_fields_only,
        })
    }
}

impl ParsePlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &[];

    fn parse_event(
        &mut self,
        event_input: &EventInput,
        parse_input: &ParseInput,
    ) -> anyhow::Result<()> {
        let event = event_input.event()?;
        let event = event.load_any()?;
        let tid = event.metadata.tid;

        let entry = self.table_with_static_fields_only.create_entry()?;
        dbg!(entry.borrow_mut().nested.name());

        let entry = self.thread_table.get_entry(&parse_input.reader, &tid)?;

        let mut num = entry
            .read_field(&parse_input.reader, &self.sample_field)
            .unwrap_or_default();
        num += 1;
        entry.write_field(&parse_input.writer, &self.sample_field, &num)?;
        Ok(())
    }
}

plugin!(DummyPlugin);
parse_plugin!(DummyPlugin);
