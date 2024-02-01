use std::ffi::{c_char, CStr};
use std::marker::PhantomData;
use std::mem::ManuallyDrop;

use thiserror::Error;

use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_owner_t, ss_plugin_state_data, ss_plugin_state_type,
    ss_plugin_table_entry_t, ss_plugin_table_fieldinfo, ss_plugin_table_fields_vtable_ext,
    ss_plugin_table_iterator_func_t, ss_plugin_table_iterator_state_t,
    ss_plugin_table_reader_vtable_ext, ss_plugin_table_t, ss_plugin_table_writer_vtable_ext,
};

use crate::plugin::error::LastError;
use crate::plugin::tables::entry::{TableEntry, TableEntryReader};
use crate::plugin::tables::field::FromDataTag;
use crate::plugin::tables::key::{TableKey, ToData};
use crate::strings::from_ptr::{try_str_from_ptr, FromPtrError};
use crate::tables::TypedTableField;
use crate::FailureReason;

pub struct TypedTable<K: TableKey> {
    table: *mut ss_plugin_table_t,
    fields_vtable: *const ss_plugin_table_fields_vtable_ext,
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

impl<K: TableKey> TypedTable<K> {
    pub(crate) fn new(
        table: *mut ss_plugin_table_t,
        fields_vtable: *const ss_plugin_table_fields_vtable_ext,
        owner: *mut ss_plugin_owner_t,
        get_owner_last_error: Option<
            unsafe extern "C" fn(o: *mut ss_plugin_owner_t) -> *const c_char,
        >,
    ) -> TypedTable<K> {
        TypedTable {
            table,
            fields_vtable,
            key_type: PhantomData,
            last_error: LastError::new(owner, get_owner_last_error),
        }
    }

    // fields
    pub fn list_fields(
        &self,
        fields_vtable: &ss_plugin_table_fields_vtable_ext,
    ) -> &[ss_plugin_table_fieldinfo] {
        match fields_vtable.list_table_fields {
            Some(list_table_fields) => {
                let mut num_fields = 0u32;
                let fields = unsafe { list_table_fields(self.table, &mut num_fields as *mut _) };

                unsafe { std::slice::from_raw_parts(fields, num_fields as usize) }
            }
            None => &[],
        }
    }

    pub fn get_field<V: FromDataTag + ?Sized>(
        &self,
        name: &CStr,
    ) -> Result<TypedTableField<V>, FailureReason> {
        let fields_vtable = unsafe { self.fields_vtable.as_ref() }.ok_or(FailureReason::Failure)?;
        let get_table_field = fields_vtable
            .get_table_field
            .ok_or(FailureReason::Failure)?;
        let table = unsafe {
            get_table_field(
                self.table,
                name.as_ptr().cast(),
                V::Actual::TYPE_ID as ss_plugin_state_type,
            )
            .as_mut()
            .ok_or(FailureReason::Failure)?
        };
        Ok(TypedTableField::<V>::new(table as *mut _))
    }

    pub fn add_field<V: FromDataTag + ?Sized>(
        &self,
        name: &CStr,
    ) -> Result<TypedTableField<V>, FailureReason> {
        let fields_vtable = unsafe { self.fields_vtable.as_ref() }.ok_or(FailureReason::Failure)?;
        let add_table_field = fields_vtable
            .add_table_field
            .ok_or(FailureReason::Failure)?;

        let table = unsafe {
            add_table_field(
                self.table,
                name.as_ptr().cast(),
                V::Actual::TYPE_ID as ss_plugin_state_type,
            )
            .as_mut()
        }
        .ok_or(FailureReason::Failure)?;
        Ok(TypedTableField::<V>::new(table as *mut _))
    }

    // reads
    pub fn get_name(
        &self,
        reader_vtable: &ss_plugin_table_reader_vtable_ext,
    ) -> Result<&str, TableError> {
        let get_table_name = reader_vtable.get_table_name.ok_or(TableError::BadVtable)?;
        Ok(try_str_from_ptr(
            unsafe { get_table_name(self.table) },
            self,
        )?)
    }

    pub fn get_size(
        &self,
        reader_vtable: &ss_plugin_table_reader_vtable_ext,
    ) -> Result<usize, TableError> {
        let get_table_size = reader_vtable.get_table_size.ok_or(TableError::BadVtable)?;
        Ok(unsafe { get_table_size(self.table) } as usize)
    }

    pub fn get_entry(
        &self,
        reader_vtable: &ss_plugin_table_reader_vtable_ext,
        key: &K,
    ) -> Option<TableEntryReader> {
        let entry = unsafe {
            reader_vtable.get_table_entry?(self.table, &key.to_data() as *const _).as_mut()
        }?;
        Some(TableEntryReader {
            table: self.table,
            reader_vtable: reader_vtable as *const _,
            entry: entry as *mut _,
            last_error: self.last_error.clone(),

            entry_value: ss_plugin_state_data { u64_: 0 },
        })
    }

    pub fn iter_entries<F>(
        &self,
        reader_vtable: &ss_plugin_table_reader_vtable_ext,
        mut func: F,
    ) -> bool
    where
        F: FnMut(&mut TableEntryReader) -> bool,
    {
        let Some(iterate_entries) = reader_vtable.iterate_entries else {
            return false;
        };

        iter_inner(
            self.table,
            iterate_entries,
            move |s: *mut ss_plugin_table_entry_t| {
                // Do not call the destructor on TableEntryReader: we do not have
                // our own refcount for it, just borrowing
                let mut entry = ManuallyDrop::new(TableEntryReader {
                    table: self.table,
                    entry: s,
                    reader_vtable,
                    last_error: self.last_error.clone(),
                    entry_value: ss_plugin_state_data { u64_: 0 },
                });

                func(&mut entry)
            },
        )
    }

    pub fn iter_entries_mut<F>(
        &self,
        reader_vtable: &ss_plugin_table_reader_vtable_ext,
        writer_vtable: &ss_plugin_table_writer_vtable_ext,
        mut func: F,
    ) -> bool
    where
        F: FnMut(&mut TableEntry) -> bool,
    {
        let Some(iterate_entries) = reader_vtable.iterate_entries else {
            return false;
        };

        iter_inner(
            self.table,
            iterate_entries,
            move |s: *mut ss_plugin_table_entry_t| {
                // Do not call the destructor on TableEntryReader: we do not have
                // our own refcount for it, just borrowing
                let mut entry = ManuallyDrop::new(
                    TableEntryReader {
                        table: self.table,
                        entry: s,
                        reader_vtable,
                        last_error: self.last_error.clone(),
                        entry_value: ss_plugin_state_data { u64_: 0 },
                    }
                    .with_writer(writer_vtable),
                );

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
