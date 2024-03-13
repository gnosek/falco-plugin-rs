use std::ffi::CStr;

use anyhow::anyhow;

use falco_event::events::EventType;
use falco_plugin::base::{Plugin, TableInitInput};
use falco_plugin::parse::{EventParseInput, ParsePlugin};
use falco_plugin::tables::TypedTable;
use falco_plugin::tables::TypedTableField;
use falco_plugin::{c, parse_plugin, plugin, EventInput, FailureReason};
use falco_plugin_api::{ss_plugin_event_input, ss_plugin_event_parse_input, ss_plugin_init_input};

pub struct DummyPlugin {
    thread_table: TypedTable<i64>,
    sample_field: TypedTableField<u64>,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c!("parse-plugin-rs");
    const PLUGIN_VERSION: &'static CStr = c!("0.0.0");
    const DESCRIPTION: &'static CStr = c!("sample source plugin");
    const CONTACT: &'static CStr = c!("rust@localdomain.pl");
    type ConfigType = ();

    fn new(input: &ss_plugin_init_input, _config: Self::ConfigType) -> Result<Self, FailureReason> {
        let thread_table = input.get_table::<i64>(c!("threads"))?;
        let sample_field = thread_table.add_field::<u64>(c!("sample"))?;

        Ok(DummyPlugin {
            thread_table,
            sample_field,
        })
    }
}

impl ParsePlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &[];

    fn parse_event(
        &mut self,
        event_input: &ss_plugin_event_input,
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
