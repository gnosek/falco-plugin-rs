use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::data::{Key, Value};
use crate::plugin::tables::entry::{TableEntry, TableEntryReader};
use crate::plugin::tables::table::raw::RawTable;
use crate::plugin::tables::vtable::{TableFields, TableReader, TableWriter};
use crate::strings::from_ptr::FromPtrError;
use crate::tables::{Field, TablesInput};
use falco_plugin_api::ss_plugin_table_fieldinfo;
use std::ffi::CStr;
use std::marker::PhantomData;
use thiserror::Error;

pub(in crate::plugin::tables) mod raw;

/// # A handle for a specific table
pub struct TypedTable<K: Key> {
    raw_table: RawTable,
    last_error: LastError,
    key_type: PhantomData<K>,
}

#[derive(Debug, Error)]
pub enum TableError {
    #[error("missing vtable entry")]
    BadVtable,

    #[error("invalid C-style string")]
    FromPtrError(#[from] FromPtrError),
}

impl<K: Key> TypedTable<K> {
    pub(crate) unsafe fn new(raw_table: RawTable, last_error: LastError) -> TypedTable<K> {
        TypedTable {
            raw_table,
            key_type: PhantomData,
            last_error,
        }
    }

    /// # List the available fields
    ///
    /// **Note**: this method is of limited utility in actual plugin code (you know the fields you
    /// want to access), so it returns the unmodified structure from the plugin API, including
    /// raw pointers to C-style strings. This may change later.
    pub fn list_fields(&self, fields_vtable: &TableFields) -> &[ss_plugin_table_fieldinfo] {
        self.raw_table.list_fields(fields_vtable)
    }

    /// # Get a table field by name
    ///
    /// The field must exist in the table and must be of the type `V`, otherwise an error
    /// will be returned.
    ///
    /// Note that the field objects remembers the table it was retrieved from and accessing
    /// an entry from a different table will cause an error at runtime.
    pub fn get_field<V: Value + ?Sized>(
        &self,
        tables_input: &TablesInput,
        name: &CStr,
    ) -> Result<Field<V>, anyhow::Error> {
        let field = self.raw_table.get_field(tables_input, name)?;
        Ok(Field::new(field, self.raw_table.table))
    }

    /// # Add a table field
    ///
    /// The field will have the specified name and the type is derived from the generic argument.
    ///
    /// Note that the field objects remembers the table it was retrieved from and accessing
    /// an entry from a different table will cause an error at runtime.
    pub fn add_field<V: Value + ?Sized>(
        &self,
        tables_input: &TablesInput,
        name: &CStr,
    ) -> Result<Field<V>, anyhow::Error> {
        let field = self.raw_table.add_field(tables_input, name)?;
        Ok(Field::new(field, self.raw_table.table))
    }

    /// # Get the table name
    ///
    /// This method returns an error if the name cannot be represented as UTF-8
    pub fn get_name(&self, reader_vtable: &TableReader) -> Result<&str, TableError> {
        Ok(self.raw_table.get_name(reader_vtable)?)
    }

    /// # Get the table size
    ///
    /// Return the number of entries in the table
    pub fn get_size(&self, reader_vtable: &TableReader) -> Result<usize, TableError> {
        Ok(self.raw_table.get_size(reader_vtable))
    }

    pub(crate) fn get_entry(
        &self,
        reader_vtable: TableReader,
        key: &K,
    ) -> Option<TableEntryReader> {
        let raw_entry = unsafe { self.raw_table.get_entry(&reader_vtable, key).ok()? };
        Some(TableEntryReader {
            table: self.raw_table.table,
            reader_vtable,
            entry: raw_entry,
            last_error: self.last_error.clone(),
        })
    }

    pub(crate) fn iter_entries<F>(&self, reader_vtable: &TableReader, mut func: F) -> bool
    where
        F: FnMut(&mut TableEntryReader) -> bool,
    {
        self.raw_table.iter_entries_mut(reader_vtable, move |raw| {
            let mut entry = TableEntryReader {
                table: self.raw_table.table,
                entry: raw,
                reader_vtable: reader_vtable.clone(),
                last_error: self.last_error.clone(),
            };
            func(&mut entry)
        })
    }

    pub(crate) fn iter_entries_mut<F>(
        &self,
        reader_vtable: &TableReader,
        writer_vtable: &TableWriter,
        mut func: F,
    ) -> bool
    where
        F: FnMut(&mut TableEntry) -> bool,
    {
        self.raw_table.iter_entries_mut(reader_vtable, |raw| {
            let mut entry = TableEntryReader {
                table: self.raw_table.table,
                entry: raw,
                reader_vtable: reader_vtable.clone(),
                last_error: self.last_error.clone(),
            }
            .with_writer(writer_vtable.clone());
            func(&mut entry)
        })
    }
}
