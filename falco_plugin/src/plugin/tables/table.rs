use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::data::{Key, Value};
use crate::plugin::tables::entry::raw::RawEntry;
use crate::plugin::tables::entry::{TableEntry, TableEntryReader};
use crate::plugin::tables::vtable::{TableFields, TableReader, TableWriter};
use crate::strings::from_ptr::{try_str_from_ptr, FromPtrError};
use crate::tables::{Field, TablesInput};
use crate::FailureReason;
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_owner_t, ss_plugin_state_type, ss_plugin_table_entry_t,
    ss_plugin_table_fieldinfo, ss_plugin_table_iterator_func_t, ss_plugin_table_iterator_state_t,
    ss_plugin_table_t,
};
use std::ffi::{c_char, CStr};
use std::marker::PhantomData;
use thiserror::Error;

/// # A handle for a specific table
pub struct TypedTable<K: Key> {
    table: *mut ss_plugin_table_t,
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
    pub(crate) unsafe fn new(
        table: *mut ss_plugin_table_t,
        owner: *mut ss_plugin_owner_t,
        get_owner_last_error: unsafe extern "C" fn(o: *mut ss_plugin_owner_t) -> *const c_char,
    ) -> TypedTable<K> {
        TypedTable {
            table,
            key_type: PhantomData,
            last_error: LastError::new(owner, get_owner_last_error),
        }
    }

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
    /// Note that the field objects remembers the table it was retrieved from and accessing
    /// an entry from a different table will cause an error at runtime.
    pub fn get_field<V: Value + ?Sized>(
        &self,
        tables_input: &TablesInput,
        name: &CStr,
    ) -> Result<Field<V>, FailureReason> {
        let field = unsafe {
            (tables_input.fields_ext.get_table_field)(
                self.table,
                name.as_ptr().cast(),
                V::TYPE_ID as ss_plugin_state_type,
            )
            .as_mut()
            .ok_or(FailureReason::Failure)?
        };
        Ok(Field::<V>::new(field as *mut _, self.table))
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
    ) -> Result<Field<V>, FailureReason> {
        let table = unsafe {
            (tables_input.fields_ext.add_table_field)(
                self.table,
                name.as_ptr().cast(),
                V::TYPE_ID as ss_plugin_state_type,
            )
            .as_mut()
        }
        .ok_or(FailureReason::Failure)?;
        Ok(Field::<V>::new(table as *mut _, self.table))
    }

    /// # Get the table name
    ///
    /// This method returns an error if the name cannot be represented as UTF-8
    pub fn get_name(&self, reader_vtable: &TableReader) -> Result<&str, TableError> {
        Ok(try_str_from_ptr(
            unsafe { (reader_vtable.get_table_name)(self.table) },
            self,
        )?)
    }

    /// # Get the table size
    ///
    /// Return the number of entries in the table
    pub fn get_size(&self, reader_vtable: &TableReader) -> Result<usize, TableError> {
        Ok(unsafe { (reader_vtable.get_table_size)(self.table) } as usize)
    }

    pub(crate) fn get_entry(
        &self,
        reader_vtable: TableReader,
        key: &K,
    ) -> Option<TableEntryReader> {
        let entry = unsafe {
            (reader_vtable.get_table_entry)(self.table, &key.to_data() as *const _).as_mut()
        }?;
        let raw_entry = RawEntry {
            table: self.table,
            entry: entry as *mut _,
            destructor: Some(reader_vtable.release_table_entry),
        };
        Some(TableEntryReader {
            table: self.table,
            reader_vtable,
            entry: raw_entry,
            last_error: self.last_error.clone(),
        })
    }

    pub(crate) fn iter_entries<F>(&self, reader_vtable: &TableReader, mut func: F) -> bool
    where
        F: FnMut(&mut TableEntryReader) -> bool,
    {
        iter_inner(
            self.table,
            reader_vtable.iterate_entries,
            move |s: *mut ss_plugin_table_entry_t| {
                // Do not call the destructor on TableEntryReader: we do not have
                // our own refcount for it, just borrowing
                let entry = RawEntry {
                    table: self.table,
                    entry: s as *mut _,
                    destructor: None,
                };
                let mut entry = TableEntryReader {
                    table: self.table,
                    entry,
                    reader_vtable: reader_vtable.clone(),
                    last_error: self.last_error.clone(),
                };

                func(&mut entry)
            },
        )
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
        iter_inner(
            self.table,
            reader_vtable.iterate_entries,
            move |s: *mut ss_plugin_table_entry_t| {
                // Do not call the destructor on TableEntryReader: we do not have
                // our own refcount for it, just borrowing
                let entry = RawEntry {
                    table: self.table,
                    entry: s as *mut _,
                    destructor: None,
                };
                let mut entry = TableEntryReader {
                    table: self.table,
                    entry,
                    reader_vtable: reader_vtable.clone(),
                    last_error: self.last_error.clone(),
                }
                .with_writer(writer_vtable.clone());

                func(&mut entry)
            },
        )
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
