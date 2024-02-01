use crate::plugin::tables::entry::TableEntryReader;
use crate::plugin::tables::key::TableKey;
use crate::tables::TypedTable;
use falco_plugin_api::ss_plugin_table_reader_vtable_ext;

pub struct TableReader {
    vtable: *const ss_plugin_table_reader_vtable_ext,
}

impl TableReader {
    pub fn new(vtable: *const ss_plugin_table_reader_vtable_ext) -> Self {
        Self { vtable }
    }

    pub fn table_entry<K: TableKey>(
        &self,
        table: &TypedTable<K>,
        key: &K,
    ) -> Option<TableEntryReader> {
        unsafe { table.get_entry(self.vtable.as_ref()?, key) }
    }
}
