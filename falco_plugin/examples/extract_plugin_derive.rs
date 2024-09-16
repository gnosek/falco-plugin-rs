use std::ffi::{CStr, CString};
use std::rc::Rc;

use anyhow::Error;

use falco_event::events::types::EventType;
use falco_plugin::base::Plugin;
use falco_plugin::extract::{
    field, ExtractFieldInfo, ExtractFieldRequestArg, ExtractPlugin, ExtractRequest,
};
use falco_plugin::tables::import::{Entry, Field, Table, TableMetadata};
use falco_plugin::tables::TablesInput;
use falco_plugin::{extract_plugin, plugin};

type ThreadTable = Table<i64, Thread>;
type Thread = Entry<Rc<ThreadMetadata>>;

#[derive(TableMetadata)]
#[entry_type(Thread)]
struct ThreadMetadata {
    comm: Field<CStr, Thread>,
    fd: Field<FdTable, Thread>,

    #[custom]
    color: Field<u64, Thread>,
}

type FdTable = Table<i64, Fd>;
type Fd = Entry<Rc<FdMetadata>>;

#[derive(TableMetadata)]
#[entry_type(Fd)]
struct FdMetadata {
    #[name(c"type")]
    fd_type: Field<u8, Fd>,
}

pub struct DummyPlugin {
    thread_table: ThreadTable,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"extract-plugin-rs";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"sample extract plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, anyhow::Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get tables input"))?;
        let thread_table = input.get_table(c"threads")?;

        Ok(DummyPlugin { thread_table })
    }
}

impl DummyPlugin {
    fn extract_sample(
        &mut self,
        ExtractRequest { table_reader, .. }: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<CString, Error> {
        let entry = self.thread_table.get_entry(table_reader, &1i64)?;
        Ok(CString::from(entry.get_comm(table_reader)?))
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
            .get_fd_by_key(table_reader, &0)?
            .get_fd_type(table_reader)
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
