use crate::plugin::tables::data::Key;
use crate::plugin::tables::entry::raw::RawEntry;
use crate::plugin::tables::table::raw::RawTable;
use crate::plugin::tables::vtable::TableReader;
use crate::tables::TablesInput;
use falco_plugin_api::ss_plugin_table_t;
use std::rc::Rc;

/// Metadata for tables
///
/// This is needed for table-valued fields but is also reused for top-level tables,
/// just to avoid duplicate implementations
pub trait TableMetadata: Sized {
    /// Create table metadata for a particular table
    ///
    /// This boils down to creating metadata for each field, most of them being no-ops
    /// but table-valued fields will fetch their fields' metadata recursively here
    fn new(raw_table: &RawTable, tables_input: &TablesInput) -> Result<Self, anyhow::Error>;
}

impl<M: TableMetadata> TableMetadata for Rc<M> {
    fn new(raw_table: &RawTable, tables_input: &TablesInput) -> Result<Self, anyhow::Error> {
        Ok(Rc::new(M::new(raw_table, tables_input)?))
    }
}

/// A trait describing structs that can be stored as table entries
pub trait Entry {
    /// metadata for the entry (for each field)
    type Metadata: TableMetadata + Clone;

    /// wrap an opaque FFI pointer in an Entry instance
    fn new(raw_entry: RawEntry, table: *mut ss_plugin_table_t, metadata: Self::Metadata) -> Self;

    /// return a reference to the entry's metadata
    fn get_metadata(&self) -> &Self::Metadata;

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

    /// the type of the entry metadata
    type Metadata: TableMetadata + Clone;

    /// create a new table
    ///
    /// is_nested is true for tables that are fields in other tables, false for top-level tables
    fn new(raw_table: RawTable, metadata: Self::Metadata, is_nested: bool) -> Self;

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