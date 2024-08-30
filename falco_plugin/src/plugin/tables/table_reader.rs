use crate::plugin::tables::data::Key;
use crate::plugin::tables::entry::TableEntryReader;
use crate::tables::TypedTable;
use falco_plugin_api::ss_plugin_table_reader_vtable_ext;

/// # An accessor object to look up table entries for read-only access
pub struct TableReader {
    vtable: crate::plugin::tables::vtable::TableReader,
}

impl TableReader {
    pub(crate) unsafe fn new(vtable: *const ss_plugin_table_reader_vtable_ext) -> Option<Self> {
        let vtable =
            crate::plugin::tables::vtable::TableReader::try_from(unsafe { vtable.as_ref()? })
                .ok()?;

        Some(Self { vtable })
    }

    /// # Get a table entry object corresponding to `key`
    ///
    /// This method looks up `key` in the table described by `table` and returns
    /// the corresponding [entry](`TableEntryReader`), which can be used to read individual fields.
    ///
    /// Returns [`None`] if the entry cannot be found
    pub fn table_entry<K: Key>(&self, table: &TypedTable<K>, key: &K) -> Option<TableEntryReader> {
        table.get_entry(self.vtable.clone(), key)
    }

    /// # Iterate over all entries in a table with read-only access
    ///
    /// The closure is called once for each table entry with a corresponding [`TableEntryReader`]
    /// object as a parameter.
    ///
    /// The iteration stops when either all entries have been processed or the closure returns `false`.
    pub fn iter_entries<F, K>(&self, table: &TypedTable<K>, func: F) -> bool
    where
        F: FnMut(&mut TableEntryReader) -> bool,
        K: Key,
    {
        table.iter_entries(&self.vtable, func)
    }
}
