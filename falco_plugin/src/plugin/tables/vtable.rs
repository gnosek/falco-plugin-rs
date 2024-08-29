use std::ffi::CStr;
use thiserror::Error;

use crate::plugin::error::as_result::{AsResult, WithLastError};
use crate::plugin::error::last_error::LastError;
use crate::plugin::exported_tables::wrappers::{fields_vtable, reader_vtable, writer_vtable};
use crate::tables::{ExportedTable, TableData, TypedTable};
use falco_plugin_api::{
    ss_plugin_init_input, ss_plugin_owner_t, ss_plugin_rc, ss_plugin_state_type,
    ss_plugin_table_field_t, ss_plugin_table_fieldinfo, ss_plugin_table_fields_vtable,
    ss_plugin_table_fields_vtable_ext, ss_plugin_table_info, ss_plugin_table_input,
    ss_plugin_table_reader_vtable, ss_plugin_table_t, ss_plugin_table_writer_vtable,
};

#[derive(Error, Debug)]
pub enum TableError {
    #[error("Missing entry {0} in table operations vtable")]
    BadVtable(&'static str),
}

#[derive(Debug)]
pub struct TableReader {
    pub(in crate::plugin::tables) get_table_name:
        unsafe extern "C" fn(t: *mut ss_plugin_table_t) -> *const ::std::os::raw::c_char,
    pub(in crate::plugin::tables) get_table_size:
        unsafe extern "C" fn(t: *mut ss_plugin_table_t) -> u64,
}

#[derive(Debug)]
pub struct TableFields {
    pub(in crate::plugin::tables) list_table_fields:
        unsafe extern "C" fn(
            t: *mut ss_plugin_table_t,
            nfields: *mut u32,
        ) -> *const ss_plugin_table_fieldinfo,
    pub(in crate::plugin::tables) get_table_field:
        unsafe extern "C" fn(
            t: *mut ss_plugin_table_t,
            name: *const ::std::os::raw::c_char,
            data_type: ss_plugin_state_type,
        ) -> *mut ss_plugin_table_field_t,
    pub(in crate::plugin::tables) add_table_field:
        unsafe extern "C" fn(
            t: *mut ss_plugin_table_t,
            name: *const ::std::os::raw::c_char,
            data_type: ss_plugin_state_type,
        ) -> *mut ss_plugin_table_field_t,
}

impl TableFields {
    fn try_from(fields_ext: &ss_plugin_table_fields_vtable_ext) -> Result<Self, TableError> {
        Ok(TableFields {
            list_table_fields: fields_ext
                .list_table_fields
                .ok_or(TableError::BadVtable("list_table_fields"))?,
            get_table_field: fields_ext
                .get_table_field
                .ok_or(TableError::BadVtable("get_table_field"))?,
            add_table_field: fields_ext
                .add_table_field
                .ok_or(TableError::BadVtable("add_table_field"))?,
        })
    }
}

#[derive(Debug)]
/// An object containing table-related vtables
///
/// It's used as a token to prove you're allowed to read/write tables
/// or manage their fields
pub struct TablesInput {
    owner: *mut ss_plugin_owner_t,
    get_owner_last_error:
        unsafe extern "C" fn(o: *mut ss_plugin_owner_t) -> *const std::ffi::c_char,

    pub(in crate::plugin::tables) list_tables: unsafe extern "C" fn(
        o: *mut ss_plugin_owner_t,
        ntables: *mut u32,
    )
        -> *mut ss_plugin_table_info,
    pub(in crate::plugin::tables) get_table: unsafe extern "C" fn(
        o: *mut ss_plugin_owner_t,
        name: *const ::std::os::raw::c_char,
        key_type: ss_plugin_state_type,
    ) -> *mut ss_plugin_table_t,
    pub(in crate::plugin::tables) add_table: unsafe extern "C" fn(
        o: *mut ss_plugin_owner_t,
        in_: *const ss_plugin_table_input,
    ) -> ss_plugin_rc,

    /// accessor object for manipulating fields
    pub(in crate::plugin::tables) fields_ext: TableFields,
}

impl TablesInput {
    pub(crate) fn try_from(value: &ss_plugin_init_input) -> Result<Option<Self>, TableError> {
        if let Some(table_init_input) = unsafe { value.tables.as_ref() } {
            let fields_ext = unsafe {
                table_init_input
                    .fields_ext
                    .as_ref()
                    .ok_or(TableError::BadVtable("fields_ext"))?
            };

            let get_owner_last_error = value
                .get_owner_last_error
                .ok_or(TableError::BadVtable("get_owner_last_error"))?;

            Ok(Some(TablesInput {
                owner: value.owner,
                get_owner_last_error,
                list_tables: table_init_input
                    .list_tables
                    .ok_or(TableError::BadVtable("list_tables"))?,
                get_table: table_init_input
                    .get_table
                    .ok_or(TableError::BadVtable("get_table"))?,
                add_table: table_init_input
                    .add_table
                    .ok_or(TableError::BadVtable("add_table"))?,
                fields_ext: TableFields::try_from(fields_ext)?,
            }))
        } else {
            Ok(None)
        }
    }
}

impl TablesInput {
    /// # List the available tables
    ///
    /// **Note**: this method is of limited utility in actual plugin code (you know the tables you
    /// want to access), so it returns the unmodified structure from the plugin API, including
    /// raw pointers to C-style strings. This may change later.
    pub fn list_tables(&self) -> &[ss_plugin_table_info] {
        let mut num_tables = 0u32;
        let tables = unsafe { (self.list_tables)(self.owner, &mut num_tables as *mut _) };
        if tables.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(tables, num_tables as usize) }
        }
    }

    /// # Import a table from the Falco plugin API
    ///
    /// The key type is verified by the plugin API, so this method will return
    /// an error on mismatch
    pub fn get_table<K: TableData>(&self, name: &CStr) -> Result<TypedTable<K>, anyhow::Error> {
        let table = unsafe {
            (self.get_table)(
                self.owner,
                name.as_ptr().cast(),
                K::TYPE_ID as ss_plugin_state_type,
            )
        };
        if table.is_null() {
            Err(anyhow::anyhow!("Could not get table {:?}", name)).with_last_error(&self.last_error)
        } else {
            // Safety: we pass the data directly from FFI, the framework would never lie to us, right?
            Ok(unsafe { TypedTable::<K>::new(table, self.owner, self.get_owner_last_error) })
        }
    }

    /// # Export a table to the Falco plugin API
    pub fn add_table<K: TableData, T: ExportedTable<Key = K>>(
        &self,
        table: T,
    ) -> Result<&'static mut T, anyhow::Error> {
        let mut reader_vtable_ext = reader_vtable::<T>();
        let mut writer_vtable_ext = writer_vtable::<T>();
        let mut fields_vtable_ext = fields_vtable::<T>();

        let mut table = Box::new(table);
        let table_ptr = table.as_mut() as *mut T;

        // Note: we lend the ss_plugin_table_input to the FFI api and do not need
        // to hold on to it (everything is copied out), but the name field is copied
        // as a pointer, so the name we receive must be a 'static ref
        let table_input = ss_plugin_table_input {
            name: table.name().as_ptr(),
            key_type: K::TYPE_ID as ss_plugin_state_type,
            table: table_ptr.cast(),
            reader: ss_plugin_table_reader_vtable {
                get_table_name: reader_vtable_ext.get_table_name,
                get_table_size: reader_vtable_ext.get_table_size,
                get_table_entry: reader_vtable_ext.get_table_entry,
                read_entry_field: reader_vtable_ext.read_entry_field,
            },
            writer: ss_plugin_table_writer_vtable {
                clear_table: writer_vtable_ext.clear_table,
                erase_table_entry: writer_vtable_ext.erase_table_entry,
                create_table_entry: writer_vtable_ext.create_table_entry,
                destroy_table_entry: writer_vtable_ext.destroy_table_entry,
                add_table_entry: writer_vtable_ext.add_table_entry,
                write_entry_field: writer_vtable_ext.write_entry_field,
            },
            fields: ss_plugin_table_fields_vtable {
                list_table_fields: fields_vtable_ext.list_table_fields,
                get_table_field: fields_vtable_ext.get_table_field,
                add_table_field: fields_vtable_ext.add_table_field,
            },
            reader_ext: &mut reader_vtable_ext as *mut _,
            writer_ext: &mut writer_vtable_ext as *mut _,
            fields_ext: &mut fields_vtable_ext as *mut _,
        };

        let last_error = unsafe { LastError::new(self.owner, self.get_owner_last_error) };

        unsafe { (self.add_table)(self.owner, &table_input as *const _) }
            .as_result()
            .with_last_error(&last_error)?;
        // There is no API for destroying a table, so we leak the pointer. At least we can have
        // a &'static back
        Ok(Box::leak(table))
    }
}
