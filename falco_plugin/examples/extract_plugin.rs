use std::ffi::{CStr, CString};

use anyhow::{anyhow, Error};

use falco_event::events::types::EventType;
use falco_plugin::base::{Plugin, TableInitInput};
use falco_plugin::extract::{
    field, EventInput, ExtractFieldInfo, ExtractFieldRequestArg, ExtractPlugin,
};
use falco_plugin::tables::TypedTableField;
use falco_plugin::tables::{TableReader, TypedTable};
use falco_plugin::{extract_plugin, plugin};
use falco_plugin_api::ss_plugin_init_input;

pub struct DummyPlugin {
    thread_table: TypedTable<i64>,
    comm_field: TypedTableField<CStr>,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"extract-plugin-rs";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"sample extract plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: &ss_plugin_init_input, _config: Self::ConfigType) -> Result<Self, anyhow::Error> {
        let thread_table = input.get_table::<i64>(c"threads")?;
        let comm_field = thread_table.get_field::<CStr>(c"comm")?;

        Ok(DummyPlugin {
            thread_table,
            comm_field,
        })
    }
}

impl DummyPlugin {
    fn extract_sample(
        &mut self,
        _context: &mut (),
        _arg: ExtractFieldRequestArg,
        _input: &EventInput,
        tables: &TableReader,
    ) -> Result<CString, Error> {
        let mut reader = tables
            .table_entry(&self.thread_table, &1i64)
            .ok_or_else(|| anyhow!("tid 1 not found"))?;
        dbg!(reader.read_field(&self.comm_field)).ok();
        Ok(c"hello".to_owned())
    }

    fn extract_sample_strs(
        &mut self,
        _context: &mut (),
        _arg: ExtractFieldRequestArg,
        _input: &EventInput,
        _tables: &TableReader,
    ) -> Result<Vec<CString>, Error> {
        Ok(vec![c"hello".to_owned(), c"bybye".to_owned()])
    }

    //noinspection DuplicatedCode
    fn extract_sample_nums(
        &mut self,
        _context: &mut (),
        _arg: ExtractFieldRequestArg,
        _input: &EventInput,
        _tables: &TableReader,
    ) -> Result<Vec<u64>, Error> {
        Ok(vec![5u64, 10u64])
    }
}

impl ExtractPlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &[];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("example.msg", &Self::extract_sample),
        field("example.msgs", &Self::extract_sample_strs),
        field("example.nums", &Self::extract_sample_nums),
    ];
}

plugin!(DummyPlugin);
extract_plugin!(DummyPlugin);
