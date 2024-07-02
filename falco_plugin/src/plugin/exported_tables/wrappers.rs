use std::ffi::{c_char, CStr};
use std::rc::Rc;

use num_traits::FromPrimitive;

use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_rc, ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_SUCCESS,
    ss_plugin_state_data, ss_plugin_state_type, ss_plugin_table_entry_t, ss_plugin_table_field_t,
    ss_plugin_table_fieldinfo, ss_plugin_table_fields_vtable_ext, ss_plugin_table_iterator_func_t,
    ss_plugin_table_iterator_state_t, ss_plugin_table_reader_vtable_ext, ss_plugin_table_t,
    ss_plugin_table_writer_vtable_ext,
};

use crate::plugin::error::FfiResult;
use crate::plugin::exported_tables::ExportedTable;
use crate::plugin::tables::data::{FieldTypeId, TableData};

// SAFETY: `table` must be a valid pointer to T
unsafe extern "C" fn get_table_name<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
) -> *const c_char {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return std::ptr::null_mut();
        };
        table.name().as_ptr()
    }
}

// SAFETY: `table` must be a valid pointer to T
unsafe extern "C" fn get_table_size<T: ExportedTable>(table: *mut ss_plugin_table_t) -> u64 {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return 0;
        };
        table.size() as u64
    }
}

// SAFETY: `table` must be a valid pointer to T
// SAFETY: `key` must be a valid pointer to ss_plugin_state_data
unsafe extern "C" fn get_table_entry<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
    key: *const ss_plugin_state_data,
) -> *mut ss_plugin_table_entry_t {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return std::ptr::null_mut();
        };
        let Some(key) = key.as_ref() else {
            return std::ptr::null_mut();
        };

        let key = T::Key::from_data(key);
        match table.lookup(key) {
            Some(entry) => Box::into_raw(Box::new(entry)) as *mut _,
            None => std::ptr::null_mut(),
        }
    }
}

// SAFETY: all pointers must be valid
unsafe extern "C" fn read_entry_field<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
    entry: *mut ss_plugin_table_entry_t,
    field: *const ss_plugin_table_field_t,
    out: *mut ss_plugin_state_data,
) -> ss_plugin_rc {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(entry) = (entry as *mut Rc<T::Entry>).as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(field) = (field as *const Rc<T::Field>).as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(out) = out.as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        table.get_field_value(entry, field, out).status_code()
    }
}

// SAFETY: all pointers must be valid
unsafe extern "C" fn release_table_entry<T: ExportedTable>(
    _table: *mut ss_plugin_table_t,
    entry: *mut ss_plugin_table_entry_t,
) {
    if !entry.is_null() {
        unsafe {
            drop(Box::from_raw(entry as *mut Rc<T::Entry>));
        }
    }
}

// SAFETY: all pointers must be valid
unsafe extern "C" fn iterate_entries<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
    func: ss_plugin_table_iterator_func_t,
    state: *mut ss_plugin_table_iterator_state_t,
) -> ss_plugin_bool {
    let Some(func) = func else {
        return 0;
    };
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return 0;
        };

        table.iterate_entries(|e| {
            let entry = e as *mut _ as *mut ss_plugin_table_entry_t;
            func(state, entry) != 0
        });
    }

    1
}

// SAFETY: `table` must be a valid pointer to T
unsafe extern "C" fn clear_table<T: ExportedTable>(table: *mut ss_plugin_table_t) -> ss_plugin_rc {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        table.clear();
    }
    ss_plugin_rc_SS_PLUGIN_SUCCESS
}

// TODO(spec) is removing a nonexistent entry an error?
// SAFETY: all pointers must be valid
unsafe extern "C" fn erase_table_entry<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
    key: *const ss_plugin_state_data,
) -> ss_plugin_rc {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(key) = key.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let key = T::Key::from_data(key);
        table.erase(key);
    }
    ss_plugin_rc_SS_PLUGIN_SUCCESS
}

extern "C" fn create_table_entry<T: ExportedTable>(
    _table: *mut ss_plugin_table_t,
) -> *mut ss_plugin_table_entry_t {
    Box::into_raw(Box::new(T::create_entry())).cast()
}

// TODO(spec) what if the entry already exists?
// SAFETY: all pointers must be valid
unsafe extern "C" fn add_table_entry<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
    key: *const ss_plugin_state_data,
    entry: *mut ss_plugin_table_entry_t,
) -> *mut ss_plugin_table_entry_t {
    if entry.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return std::ptr::null_mut();
        };
        let Some(key) = key.as_ref() else {
            return std::ptr::null_mut();
        };
        let key = T::Key::from_data(key);
        let entry = Box::from_raw(entry as *mut Rc<T::Entry>);

        match table.add(key, *entry) {
            Some(entry) => Box::into_raw(Box::new(entry)) as *mut _,
            None => std::ptr::null_mut(),
        }
    }
}

// SAFETY: all pointers must be valid
unsafe extern "C" fn write_entry_field<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
    entry: *mut ss_plugin_table_entry_t,
    field: *const ss_plugin_table_field_t,
    value: *const ss_plugin_state_data,
) -> ss_plugin_rc {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(entry) = (entry as *mut Rc<T::Entry>).as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(field) = (field as *const Rc<T::Field>).as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(value) = value.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        table.write(entry, field, value).status_code()
    }
}

// SAFETY: all pointers must be valid
unsafe extern "C" fn list_table_fields<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
    nfields: *mut u32,
) -> *const ss_plugin_table_fieldinfo {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return std::ptr::null_mut();
        };
        let fields = table.list_fields();
        *nfields = fields.len() as u32;
        fields.as_ptr()
    }
}

// SAFETY: all pointers must be valid
unsafe extern "C" fn get_table_field<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
    name: *const c_char,
    data_type: ss_plugin_state_type,
) -> *mut ss_plugin_table_field_t {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return std::ptr::null_mut();
        };
        let Some(data_type) = FieldTypeId::from_usize(data_type as usize) else {
            return std::ptr::null_mut();
        };
        let name = if name.is_null() {
            return std::ptr::null_mut();
        } else {
            CStr::from_ptr(name)
        };
        match table.get_field(name, data_type) {
            Some(field) => Box::into_raw(Box::new(field)) as *mut _,
            None => std::ptr::null_mut(),
        }
    }
}

// SAFETY: all pointers must be valid
unsafe extern "C" fn add_table_field<T: ExportedTable>(
    table: *mut ss_plugin_table_t,
    name: *const c_char,
    data_type: ss_plugin_state_type,
) -> *mut ss_plugin_table_field_t {
    unsafe {
        let Some(table) = (table as *mut T).as_mut() else {
            return std::ptr::null_mut();
        };
        let Some(data_type) = FieldTypeId::from_usize(data_type as usize) else {
            return std::ptr::null_mut();
        };
        let name = if name.is_null() {
            return std::ptr::null_mut();
        } else {
            CStr::from_ptr(name)
        };
        match table.add_field(name, data_type, false) {
            Some(field) => Box::into_raw(Box::new(field)) as *mut _,
            None => std::ptr::null_mut(),
        }
    }
}

pub(crate) fn reader_vtable<T: ExportedTable>() -> ss_plugin_table_reader_vtable_ext {
    ss_plugin_table_reader_vtable_ext {
        get_table_name: Some(get_table_name::<T>),
        get_table_size: Some(get_table_size::<T>),
        get_table_entry: Some(get_table_entry::<T>),
        read_entry_field: Some(read_entry_field::<T>),
        release_table_entry: Some(release_table_entry::<T>),
        iterate_entries: Some(iterate_entries::<T>),
    }
}

pub(crate) fn writer_vtable<T: ExportedTable>() -> ss_plugin_table_writer_vtable_ext {
    ss_plugin_table_writer_vtable_ext {
        clear_table: Some(clear_table::<T>),
        erase_table_entry: Some(erase_table_entry::<T>),
        create_table_entry: Some(create_table_entry::<T>),
        destroy_table_entry: Some(release_table_entry::<T>), // same as release_table_entry
        add_table_entry: Some(add_table_entry::<T>),
        write_entry_field: Some(write_entry_field::<T>),
    }
}

pub(crate) fn fields_vtable<T: ExportedTable>() -> ss_plugin_table_fields_vtable_ext {
    ss_plugin_table_fields_vtable_ext {
        list_table_fields: Some(list_table_fields::<T>),
        get_table_field: Some(get_table_field::<T>),
        add_table_field: Some(add_table_field::<T>),
    }
}
