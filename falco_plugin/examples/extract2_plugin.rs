use std::ffi::{CStr, CString};

use anyhow::{anyhow, Error};

use falco_event::events::types::EventType;
use falco_plugin::base::Plugin;
use falco_plugin::extract::{
    field, EventInput, ExtractFieldInfo, ExtractFieldRequestArg, ExtractPlugin,
};
use falco_plugin::tables::{TableReader, TypedTable};
use falco_plugin::tables::{TablesInput, TypedTableField};
use falco_plugin::{extract_plugin, plugin};

pub struct DummyPlugin {
    thread_table: TypedTable<i64>,
    sample_field: TypedTableField<u64>,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"extract2-plugin-rs";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"sample extract plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, anyhow::Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get tables input"))?;

        let thread_table = input.get_table::<i64>(c"threads")?;
        let sample_field = thread_table.get_field::<u64>(&input, c"sample")?;

        Ok(DummyPlugin {
            thread_table,
            sample_field,
        })
    }
}

impl DummyPlugin {
    fn extract_sample(
        &mut self,
        _context: &mut (),
        _arg: ExtractFieldRequestArg,
        _input: &EventInput,
        _tables: &TableReader,
    ) -> Result<CString, Error> {
        Ok(c"hello".to_owned())
    }

    fn extract_sample_strs(
        &mut self,
        _context: &mut (),
        _arg: ExtractFieldRequestArg,
        _input: &EventInput,
        _tables: &TableReader,
    ) -> Result<Vec<CString>, Error> {
        Ok(vec![c"hello".to_owned(), c"byebye".to_owned()])
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

    fn extract_sample_num(
        &mut self,
        _context: &mut (),
        _arg: ExtractFieldRequestArg,
        input: &EventInput,
        tables: &TableReader,
    ) -> Result<u64, Error> {
        let tid = input.event()?.metadata.tid;
        let mut reader = tables
            .table_entry(&self.thread_table, &tid)
            .ok_or_else(|| anyhow!("tid not found"))?;

        reader.read_field(&self.sample_field).copied()
    }
}

impl ExtractPlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &[];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("example.msg", &Self::extract_sample),
        field("example.nums", &Self::extract_sample_nums),
        field("example.msgs", &Self::extract_sample_strs),
        field("example.num", &Self::extract_sample_num),
    ];
}

plugin!(DummyPlugin);
extract_plugin!(DummyPlugin);
