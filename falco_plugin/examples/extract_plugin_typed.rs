use std::ffi::{CStr, CString};

use anyhow::Error;

use falco_event::events::types::EventType;
use falco_plugin::base::Plugin;
use falco_plugin::extract::{
    field, ExtractFieldInfo, ExtractFieldRequestArg, ExtractPlugin, ExtractRequest,
};
use falco_plugin::tables::import::{Field, RuntimeEntry, Table};
use falco_plugin::tables::TablesInput;
use falco_plugin::{extract_plugin, plugin};

struct ThreadTable;
struct FdTable;

pub struct DummyPlugin {
    thread_table: Table<i64, RuntimeEntry<ThreadTable>>,
    comm_field: Field<CStr, RuntimeEntry<ThreadTable>>,
    #[allow(dead_code)]
    color_field: Field<u64, RuntimeEntry<ThreadTable>>,
    fd_field: Field<Table<i64, RuntimeEntry<FdTable>>, RuntimeEntry<ThreadTable>>,
    fd_type_field: Field<u8, RuntimeEntry<FdTable>>,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"extract-plugin-rs";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"sample extract plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, anyhow::Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;

        let thread_table: Table<i64, RuntimeEntry<ThreadTable>> = input.get_table(c"threads")?;
        let comm_field = thread_table.get_field(input, c"comm")?;
        let color_field = thread_table.add_field(input, c"color")?;
        let (fd_field, fd_type_field) =
            thread_table.get_table_field(input, c"file_descriptors", |table| {
                table.get_field(input, c"type")
            })?;

        Ok(DummyPlugin {
            thread_table,
            comm_field,
            color_field,
            fd_field,
            fd_type_field,
        })
    }
}

impl DummyPlugin {
    fn extract_sample(
        &mut self,
        ExtractRequest { table_reader, .. }: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<CString, Error> {
        self.thread_table
            .get_entry(table_reader, &1i64)?
            .read_field(table_reader, &self.comm_field)
            .ok();
        Ok(c"hello".to_owned())
    }

    fn extract_sample_strs(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Vec<CString>, Error> {
        Ok(vec![c"hello".to_owned(), c"bybye".to_owned()])
    }

    //noinspection DuplicatedCode
    fn extract_sample_nums(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Vec<u64>, Error> {
        Ok(vec![5u64, 10u64])
    }

    fn extract_sample_num2(
        &mut self,
        ExtractRequest {
            table_reader,
            event,
            ..
        }: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<u64, Error> {
        let tid = event.event()?.metadata.tid;

        self.thread_table
            .get_entry(table_reader, &tid)?
            .read_field(table_reader, &self.fd_field)?
            .get_entry(table_reader, &0)?
            .read_field(table_reader, &self.fd_type_field)
            .map(|v| v as u64)
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
        field("example.num2", &Self::extract_sample_num2),
    ];
}

plugin!(DummyPlugin);
extract_plugin!(DummyPlugin);
