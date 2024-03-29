use std::ffi::CStr;

use falco_plugin_api::{
    ss_plugin_init_input, ss_plugin_state_type, ss_plugin_table_fields_vtable,
    ss_plugin_table_info, ss_plugin_table_input, ss_plugin_table_reader_vtable,
    ss_plugin_table_writer_vtable,
};

use crate::plugin::error::AsResult;
use crate::plugin::exported_tables::wrappers::{fields_vtable, reader_vtable, writer_vtable};
use crate::plugin::exported_tables::ExportedTable;
use crate::plugin::tables::data::TableData;
use crate::plugin::tables::table::TypedTable;
use crate::FailureReason;

/// # Trait for creating and accessing tables
///
/// The workflow for using tables is somewhat peculiar and requires cooperation of the base
/// plugin init function and a capability-specific function.
///
/// To access a table, first get the table by name and store the resulting [`TypedTable`]
/// in the plugin.
///
/// Then, use [`TypedTable::get_field`] to look up each field you want to access in that table
/// and store that too.
///
/// The next steps vary slightly depending on which plugin capabilities you use.
///
/// For event parse plugins,
/// - use [`EventParseInput::table_entry`](`crate::parse::EventParseInput::table_entry`) (passing
///   the table object you stored earlier as an argument and a key to access) to get
///   a [`tables::TableEntry`](`crate::tables::TableEntry`).
///
/// - call [`read_field`](`crate::tables::TableEntry::read_field`)
///   and [`write_field`](`crate::tables::TableEntry::write_field`) methods, which finally let you
///   read and write the table field (these methods take the field object you stored earlier)
///
/// For field extraction plugins, each field extraction method gets passed a [`TableReader`](`crate::tables::TableReader`)
/// object.
/// - use the [`TableReader::table_entry`](`crate::tables::TableReader::table_entry`) method
///   to obtain a [`tables::TableEntryReader`](`crate::tables::TableEntryReader`) for a particular
///   key of a particular table.
///
/// - call the [`read_field`](`crate::tables::TableEntry::read_field`) methods, which lets you
///   read the table field (this method takes the field object you stored earlier)
///
/// ## Tables, entries and fields
///
/// The Falco plugin framework uses concrete objects (opaque pointers behind the scenes) to describe
/// tables, table entries and fields. This is somewhat different from what you're probably used to
/// but serves performance optimizations (table lookups happen in a pretty hot path!).
///
/// A table can be thought of as a map of structs, like this:
/// ```
/// use std::collections::BTreeMap;
///
/// struct MyStruct {
///     field1: u64,
///     field2: u32,
/// }
///
/// type MyTable = BTreeMap<u64, MyStruct>;
/// ```
///
/// with the important difference that the list of fields can be extended at runtime (you could e.g.
/// add a new `field3: &CStr` to `MyStruct`).
///
/// Using simple syntax, you could access the contents of `MyTable` like this, with the corresponding
/// types from the Falco plugin SDK marked:
/// ```ignore
/// let val = my_table[123].field2;
/// //        ^^^^^^^^              TypedTable<u64>
/// //        ^^^^^^^^^^^^^         TableEntry
/// //                      ^^^^^^  TypedTableField<u32>
/// ```
///
/// In the above example, the table and field objects are constant for the life of the plugin,
/// while you will create and destroy entry objects whenever you need to access a particular
/// table key.
pub trait InitInput {
    /// # List the available tables
    ///
    /// **Note**: this method is of limited utility in actual plugin code (you know the tables you
    /// want to access), so it returns the unmodified structure from the plugin API, including
    /// raw pointers to C-style strings. This may change later.
    fn list_tables(&self) -> &[ss_plugin_table_info];

    /// # Get a handle to a table
    ///
    /// Get a handle (to be passed to one of the `table_entry` functions) describing a particular
    /// table. The generic parameter must correspond to the key type of the table in question.
    fn get_table<K: TableData>(&self, name: &CStr) -> Result<TypedTable<K>, FailureReason>;

    /// # Expose a table for other plugins to use
    ///
    /// Your plugin can expose tables for other plugins. To do this, create an instance
    /// of [`tables::DynamicTable<K>`](`crate::tables::DynamicTable`) with the key type
    /// you want and pass it to this method.
    ///
    /// **Note**: At this point, there is no support for tables with predefined fields,
    /// so you will have to register any fields that your plugin wishes to use as dynamic
    /// fields. This comes with some performance overhead and may change later, e.g. by
    /// introducing a custom derive macro for the ExportedTable trait.
    fn add_table<K: TableData, T: ExportedTable<Key = K>>(
        &self,
        table: T,
    ) -> Result<&'static mut T, FailureReason>;
}

impl InitInput for ss_plugin_init_input {
    fn list_tables(&self) -> &[ss_plugin_table_info] {
        let vtable = unsafe { self.tables.as_ref() };
        match vtable.and_then(|v| v.list_tables) {
            Some(list_tables) => {
                let mut num_tables = 0u32;
                let tables = unsafe { list_tables(self.owner, &mut num_tables as *mut _) };
                unsafe { std::slice::from_raw_parts(tables, num_tables as usize) }
            }
            None => &[],
        }
    }

    fn get_table<K: TableData>(&self, name: &CStr) -> Result<TypedTable<K>, FailureReason> {
        let vtable = unsafe { self.tables.as_ref() }.ok_or(FailureReason::Failure)?;
        let fields_vtable = vtable.fields_ext as *const _;
        let table = unsafe {
            vtable.get_table.ok_or(FailureReason::Failure)?(
                self.owner,
                name.as_ptr().cast(),
                K::TYPE_ID as ss_plugin_state_type,
            )
        };
        if table.is_null() {
            Err(FailureReason::Failure)
        } else {
            // Safety: we pass the data directly from FFI, the framework would never lie to us, right?
            Ok(unsafe {
                TypedTable::<K>::new(table, fields_vtable, self.owner, self.get_owner_last_error)
            })
        }
    }

    fn add_table<K: TableData, T: ExportedTable>(
        &self,
        table: T,
    ) -> Result<&'static mut T, FailureReason> {
        let vtable = unsafe { self.tables.as_ref() }.ok_or(FailureReason::Failure)?;
        let add_table = vtable.add_table.ok_or(FailureReason::Failure)?;

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

        unsafe { add_table(self.owner, &table_input as *const _) }.as_result()?;
        // There is no API for destroying a table, so we leak the pointer. At least we can have
        // a &'static back
        Ok(Box::leak(table))
    }
}
