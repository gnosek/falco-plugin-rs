use crate::plugin::tables::data::Key;
use crate::plugin::tables::entry::raw::RawEntry;
use crate::plugin::tables::table::raw::RawTable;
use crate::plugin::tables::vtable::TableReader;
use falco_plugin_api::ss_plugin_table_t;

/// A trait describing structs that can be stored as table entries
pub trait Entry {
    fn new(raw_entry: RawEntry, table: *mut ss_plugin_table_t) -> Self;

    /// extract the raw entry from the instance
    fn into_raw(self) -> RawEntry;
}

/// A trait describing a table that can have its entries looked up
///
/// This too only exists to please the elder gods awoken in the derive macro
pub trait TableAccess: Sized {
    /// the type of the table key
    type Key;

    /// the type of the entries stored in the table
    type Entry;

    /// create a new table
    ///
    /// is_nested is true for tables that are fields in other tables, false for top-level tables
    fn new(raw_table: RawTable, is_nested: bool) -> Self;

    /// get a table entry
    fn get_entry(
        &self,
        reader_vtable: &TableReader,
        key: &Self::Key,
    ) -> Result<Self::Entry, anyhow::Error>
    where
        Self::Key: Key,
        Self::Entry: Entry;
}
