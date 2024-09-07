use crate::plugin::error::as_result::{AsResult, WithLastError};
use crate::plugin::tables::data::{Key, Value};
use crate::plugin::tables::entry::raw::RawEntry;
use crate::plugin::tables::field::raw::RawField;
use crate::plugin::tables::vtable::TableFields;
use crate::plugin::tables::vtable::{TableReader, TableWriter, TablesInput};
use crate::strings::from_ptr::{try_str_from_ptr, FromPtrError};
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_state_type, ss_plugin_table_entry_t, ss_plugin_table_fieldinfo,
    ss_plugin_table_iterator_func_t, ss_plugin_table_iterator_state_t, ss_plugin_table_t,
};
use std::ffi::CStr;

/// # A low-level representation of a table
///
/// This is a thin wrapper around the Falco plugin API and provides little type safety.
///
/// You will probably want to use [`crate::tables::Table`] or maybe [`crate::tables::RuntimeTable`]
/// instead.
pub struct RawTable {
    pub(crate) table: *mut ss_plugin_table_t,
}

impl RawTable {
    /// # List the available fields
    ///
    /// **Note**: this method is of limited utility in actual plugin code (you know the fields you
    /// want to access), so it returns the unmodified structure from the plugin API, including
    /// raw pointers to C-style strings. This may change later.
    pub fn list_fields(&self, fields_vtable: &TableFields) -> &[ss_plugin_table_fieldinfo] {
        let mut num_fields = 0u32;
        let fields =
            unsafe { (fields_vtable.list_table_fields)(self.table, &mut num_fields as *mut _) };
        if fields.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(fields, num_fields as usize) }
        }
    }

    /// # Get a table field by name
    ///
    /// The field must exist in the table and must be of the type `V`, otherwise an error
    /// will be returned.
    ///
    /// Note that you must not use fields with tables they did not come from. When using fields
    /// returned from this method, no such validation happens.
    pub fn get_field<V: Value + ?Sized>(
        &self,
        tables_input: &TablesInput,
        name: &CStr,
    ) -> Result<RawField<V>, anyhow::Error> {
        let raw_field = unsafe {
            let field = (tables_input.fields_ext.get_table_field)(
                self.table,
                name.as_ptr().cast(),
                V::TYPE_ID as ss_plugin_state_type,
            );
            field
                .as_mut()
                .ok_or(anyhow::anyhow!("Failed to get table field {:?}", name))
                .with_last_error(&tables_input.last_error)?;
            field
        };

        Ok(RawField {
            field: raw_field,
            value_type: std::marker::PhantomData,
        })
    }

    /// # Add a table field
    ///
    /// The field will have the specified name and the type is derived from the generic argument.
    ///
    /// Note that you must not use fields with tables they did not come from. When using fields
    /// returned from this method, no such validation happens.
    pub fn add_field<V: Value + ?Sized>(
        &self,
        tables_input: &TablesInput,
        name: &CStr,
    ) -> Result<RawField<V>, anyhow::Error> {
        let raw_field = unsafe {
            let field = (tables_input.fields_ext.add_table_field)(
                self.table,
                name.as_ptr().cast(),
                V::TYPE_ID as ss_plugin_state_type,
            );
            field
                .as_mut()
                .ok_or(anyhow::anyhow!("Failed to add table field {:?}", name))
                .with_last_error(&tables_input.last_error)?;
            field
        };

        Ok(RawField {
            field: raw_field,
            value_type: std::marker::PhantomData,
        })
    }

    /// # Look up an entry in `table` corresponding to `key`
    ///
    /// # Safety
    /// The key type must be the same as actually used by the table. Using the wrong type
    /// (especially using a number if the real key type is a string) will lead to UB.
    pub unsafe fn get_entry<K: Key>(
        &self,
        reader_vtable: &TableReader,
        key: &K,
    ) -> Result<RawEntry, anyhow::Error> {
        let entry =
            unsafe { (reader_vtable.get_table_entry)(self.table, &key.to_data() as *const _) };

        if entry.is_null() {
            Err(anyhow::anyhow!("table entry not found"))
        } else {
            Ok(RawEntry {
                table: self.table,
                entry: entry as *mut _,
                destructor: Some(reader_vtable.release_table_entry),
            })
        }
    }

    /// # Erase a table entry by key
    ///
    /// # Safety
    /// The key type must be the same as actually used by the table. Using the wrong type
    /// (especially using a number if the real key type is a string) will lead to UB.
    pub unsafe fn erase<K: Key>(
        &self,
        writer_vtable: &TableWriter,
        key: &K,
    ) -> Result<(), anyhow::Error> {
        Ok(
            (writer_vtable.erase_table_entry)(self.table, &key.to_data() as *const _)
                .as_result()?,
        )
    }

    /// # Create a table entry
    ///
    /// This creates an entry that's not attached to any particular key. To insert it into
    /// the table, pass it to [`RawTable::insert`]
    pub fn create_entry(&self, writer_vtable: &TableWriter) -> Result<RawEntry, anyhow::Error> {
        let entry = unsafe { (writer_vtable.create_table_entry)(self.table) };

        if entry.is_null() {
            Err(anyhow::anyhow!("Failed to create table entry"))
        } else {
            Ok(RawEntry {
                table: self.table,
                entry,
                destructor: Some(writer_vtable.destroy_table_entry),
            })
        }
    }

    /// # Insert an entry into the table
    ///
    /// This attaches an entry to a table key, making it accessible to other plugins
    ///
    /// # Safety
    /// The key type must be the same as actually used by the table. Using the wrong type
    /// (especially using a number if the real key type is a string) will lead to UB.
    pub unsafe fn insert<K: Key>(
        &self,
        writer_vtable: &TableWriter,
        key: &K,
        mut entry: RawEntry,
    ) -> Result<(), anyhow::Error> {
        let ret =
            (writer_vtable.add_table_entry)(self.table, &key.to_data() as *const _, entry.entry);

        if ret.is_null() {
            Err(anyhow::anyhow!("Failed to attach entry"))
        } else {
            entry.destructor.take();
            Ok(())
        }
    }

    /// # Get the table name
    ///
    /// This method returns an error if the name cannot be represented as UTF-8
    pub fn get_name(&self, reader_vtable: &TableReader) -> Result<&str, FromPtrError> {
        try_str_from_ptr(unsafe { (reader_vtable.get_table_name)(self.table) }, self)
    }

    /// # Get the table size
    ///
    /// Return the number of entries in the table
    pub fn get_size(&self, reader_vtable: &TableReader) -> usize {
        unsafe { (reader_vtable.get_table_size)(self.table) as usize }
    }

    /// # Iterate over all entries in a table with mutable access
    ///
    /// The closure is called once for each table entry with a corresponding [`RawEntry`]
    /// object as a parameter.
    ///
    /// The iteration stops when either all entries have been processed or the closure returns `false`.
    pub fn iter_entries_mut<F>(&self, reader_vtable: &TableReader, mut func: F) -> bool
    where
        F: FnMut(RawEntry) -> bool,
    {
        iter_inner(
            self.table,
            reader_vtable.iterate_entries,
            move |s: *mut ss_plugin_table_entry_t| {
                // Do not call the destructor on TableEntryReader: we do not have
                // our own refcount for it, just borrowing
                let raw_entry = RawEntry {
                    table: self.table,
                    entry: s,
                    destructor: None,
                };
                func(raw_entry)
            },
        )
    }

    /// # Clear the table
    ///
    /// Removes all entries from the table
    pub fn clear(&self, writer_vtable: &TableWriter) -> Result<(), anyhow::Error> {
        unsafe { Ok((writer_vtable.clear_table)(self.table).as_result()?) }
    }
}

fn iter_inner<F>(
    table: *mut ss_plugin_table_t,
    iterate_entries: unsafe extern "C" fn(
        *mut ss_plugin_table_t,
        it: ss_plugin_table_iterator_func_t,
        s: *mut ss_plugin_table_iterator_state_t,
    ) -> ss_plugin_bool,
    mut func: F,
) -> bool
where
    F: FnMut(*mut ss_plugin_table_entry_t) -> bool,
{
    extern "C" fn iter_wrapper<WF>(
        s: *mut ss_plugin_table_iterator_state_t,
        entry: *mut ss_plugin_table_entry_t,
    ) -> ss_plugin_bool
    where
        WF: FnMut(*mut ss_plugin_table_entry_t) -> bool,
    {
        unsafe {
            let Some(closure) = (s as *mut WF).as_mut() else {
                return 0;
            };
            let res = closure(entry);
            if res {
                1
            } else {
                0
            }
        }
    }

    unsafe {
        iterate_entries(
            table,
            Some(iter_wrapper::<F>),
            &mut func as *mut _ as *mut ss_plugin_table_iterator_state_t,
        ) != 0
    }
}