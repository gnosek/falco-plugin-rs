use std::ffi::{CStr, CString};

use anyhow::anyhow;

use falco_event::events::types::EventType;
use falco_plugin::base::Plugin;
use falco_plugin::parse::{EventInput, EventParseInput, ParsePlugin};
use falco_plugin::tables::{DynamicFieldValues, TablesInput, TypedTableField};
use falco_plugin::tables::{DynamicTable, TypedTable};
use falco_plugin::{parse_plugin, plugin};
use falco_plugin_api::ss_plugin_event_parse_input;
use falco_plugin_derive::TableValues;

#[derive(TableValues, Default)]
struct AnotherTable {
    #[readonly]
    int_field: u64,
    string_field: CString,

    #[hidden]
    #[allow(dead_code)]
    secret: Vec<u8>,

    #[dynamic]
    dynamic_fields: DynamicFieldValues,
}

#[derive(TableValues, Default)]
#[static_only]
struct TableWithStaticFieldsOnly {
    #[readonly]
    int_field: u64,
    string_field: CString,

    #[hidden]
    #[allow(dead_code)]
    secret: Vec<u8>,
}

pub struct DummyPlugin {
    thread_table: TypedTable<i64>,
    sample_field: TypedTableField<u64>,
    #[allow(dead_code)]
    new_table: &'static mut DynamicTable<u64>,
    #[allow(dead_code)]
    another_table: &'static mut DynamicTable<u64, AnotherTable>,
    #[allow(dead_code)]
    table_with_static_fields_only: &'static mut DynamicTable<u64, TableWithStaticFieldsOnly>,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"parse-plugin-rs";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"sample source plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, anyhow::Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get tables input"))?;

        let thread_table = input.get_table::<i64>(c"threads")?;
        let sample_field = thread_table.add_field::<u64>(&input, c"sample")?;

        let new_table = input.add_table(DynamicTable::new(c"sample"))?;
        let another_table = input.add_table(DynamicTable::new(c"another"))?;
        let table_with_static_fields_only =
            input.add_table(DynamicTable::new(c"static_fields_only"))?;

        Ok(DummyPlugin {
            thread_table,
            sample_field,
            new_table,
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
        parse_input: &ss_plugin_event_parse_input,
    ) -> anyhow::Result<()> {
        let event = event_input.event()?;
        let event = event.load_any()?;
        let tid = event.metadata.tid;

        let mut entry = parse_input
            .table_entry(&self.thread_table, &tid)
            .ok_or_else(|| anyhow!("tid not found"))?;

        let mut num = entry
            .read_field(&self.sample_field)
            .copied()
            .unwrap_or_default();
        num += 1;
        entry.write_field(&self.sample_field, &num)?;
        Ok(())
    }
}

plugin!(DummyPlugin);
parse_plugin!(DummyPlugin);
