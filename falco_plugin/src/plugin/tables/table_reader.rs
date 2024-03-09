use crate::plugin::tables::entry::TableEntryReader;
use crate::plugin::tables::key::TableKey;
use crate::tables::TypedTable;
use falco_plugin_api::ss_plugin_table_reader_vtable_ext;

/// # An accessor object to look up table entries for read-only access
pub struct TableReader {
    vtable: *const ss_plugin_table_reader_vtable_ext,
}

impl TableReader {
    pub(crate) unsafe fn new(vtable: *const ss_plugin_table_reader_vtable_ext) -> Self {
        Self { vtable }
    }

    /// # Get a table entry object corresponding to `key`
    ///
    /// This method looks up `key` in the table described by `table` and returns
    /// the corresponding [entry](`TableEntryReader`), which can be used to read individual fields.
    ///
    /// Returns [`None`] if the entry cannot be found
    pub fn table_entry<K: TableKey>(
        &self,
        table: &TypedTable<K>,
        key: &K,
    ) -> Option<TableEntryReader> {
        unsafe { table.get_entry(self.vtable.as_ref()?, key) }
    }
}
