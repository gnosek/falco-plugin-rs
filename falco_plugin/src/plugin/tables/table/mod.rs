use crate::plugin::tables::data::{Key, Value};
use crate::plugin::tables::entry::Entry;
use crate::plugin::tables::runtime_table_validator::RuntimeTableValidator;
use crate::plugin::tables::table::raw::RawTable;
use crate::plugin::tables::vtable::{TableFields, TableReader};
use crate::strings::from_ptr::FromPtrError;
use crate::tables::{Field, TableWriter, TablesInput};
use anyhow::Error;
use falco_plugin_api::ss_plugin_table_fieldinfo;
use std::ffi::CStr;
use std::marker::PhantomData;

pub(in crate::plugin::tables) mod raw;

/// # A handle for a specific table
pub struct Table<K> {
    pub(in crate::plugin::tables) raw_table: RawTable,
    pub(in crate::plugin::tables) key_type: PhantomData<K>,
}

impl<K: Key> Table<K> {
    /// Look up an entry in `table` corresponding to `key`
    pub fn get_entry(&self, reader_vtable: &TableReader, key: &K) -> Result<Entry, anyhow::Error> {
        let raw_entry = unsafe { self.raw_table.get_entry(reader_vtable, key)? };
        Ok(Entry::new(raw_entry, self.raw_table.table))
    }

    /// Erase a table entry by key
    pub fn erase(&self, writer_vtable: &TableWriter, key: &K) -> Result<(), Error> {
        unsafe { self.raw_table.erase(writer_vtable, key) }
    }

    /// Attach an entry to a table key (insert an entry to the table)
    pub fn insert(&self, writer_vtable: &TableWriter, key: &K, entry: Entry) -> Result<(), Error> {
        unsafe { self.raw_table.insert(writer_vtable, key, entry.into_raw()) }
    }
}

impl<K> Table<K> {
    pub(crate) unsafe fn new(raw_table: RawTable) -> Self {
        Table {
            raw_table,
            key_type: PhantomData,
        }
    }

    pub(in crate::plugin::tables) fn table_validator(&self) -> RuntimeTableValidator {
        RuntimeTableValidator::new(self.raw_table.table)
    }

    /// Create a new table entry (not yet attached to a key)
    pub fn create_entry(&self, writer_vtable: &TableWriter) -> Result<Entry, Error> {
        let raw_entry = self.raw_table.create_entry(writer_vtable)?;
        Ok(Entry::new(raw_entry, self.raw_table.table))
    }

    /// Remove all entries from the table
    pub fn clear(&self, writer_vtable: &TableWriter) -> Result<(), Error> {
        self.raw_table.clear(writer_vtable)
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
    ) -> Result<Field<V>, Error> {
        let field = self.raw_table.get_field(tables_input, name)?;
        Ok(Field::new(field, self.table_validator()))
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
    ) -> Result<Field<V>, Error> {
        let field = self.raw_table.add_field(tables_input, name)?;
        Ok(Field::new(field, self.table_validator()))
    }

    /// # Get the table name
    ///
    /// This method returns an error if the name cannot be represented as UTF-8
    pub fn get_name(&self, reader_vtable: &TableReader) -> Result<&str, FromPtrError> {
        self.raw_table.get_name(reader_vtable)
    }

    /// # Get the table size
    ///
    /// Return the number of entries in the table
    pub fn get_size(&self, reader_vtable: &TableReader) -> usize {
        self.raw_table.get_size(reader_vtable)
    }

    /// # Iterate over all entries in a table with mutable access
    ///
    /// The closure is called once for each table entry with a corresponding entry
    /// object as a parameter.
    ///
    /// The iteration stops when either all entries have been processed or the closure returns
    /// false.
    pub fn iter_entries_mut<F>(&self, reader_vtable: &TableReader, mut func: F) -> bool
    where
        F: FnMut(&mut Entry) -> bool,
    {
        self.raw_table.iter_entries_mut(reader_vtable, move |raw| {
            let mut entry = Entry::new(raw, self.raw_table.table);
            func(&mut entry)
        })
    }
}
