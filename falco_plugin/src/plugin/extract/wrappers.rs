use crate::plugin::base::PluginWrapper;
use crate::plugin::error::FfiResult;
use crate::plugin::extract::ExtractPlugin;
use crate::tables::TableReader;
use falco_plugin_api::ss_plugin_rc;
use falco_plugin_api::{ss_plugin_event_input, ss_plugin_rc_SS_PLUGIN_FAILURE};
use falco_plugin_api::{ss_plugin_field_extract_input, ss_plugin_t};
use std::ffi::{c_char, CString};
use std::sync::OnceLock;

pub fn plugin_get_fields<T: ExtractPlugin>() -> *const c_char {
    T::get_fields().as_ptr()
}

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_get_extract_event_types<T: ExtractPlugin>(
    numtypes: *mut u32,
    _plugin: *mut ss_plugin_t,
) -> *mut u16 {
    let types = T::EVENT_TYPES;
    unsafe { *numtypes = types.len() as u32 };
    types.as_ptr() as *const u16 as *mut u16 // this should ****really**** be const
}

//noinspection DuplicatedCode
pub fn plugin_get_extract_event_sources<T: ExtractPlugin>() -> *const c_char {
    static SOURCES: OnceLock<CString> = OnceLock::new();
    if SOURCES.get().is_none() {
        let sources = serde_json::to_string(T::EVENT_SOURCES)
            .expect("failed to serialize event source array");
        let sources =
            CString::new(sources.into_bytes()).expect("failed to add NUL to event source array");
        SOURCES
            .set(sources)
            .expect("multiple plugins not supported in a single crate");
    }

    SOURCES.get().unwrap().as_ptr()
}

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_extract_fields<T: ExtractPlugin>(
    plugin: *mut ss_plugin_t,
    event_input: *const ss_plugin_event_input,
    extract_input: *const ss_plugin_field_extract_input,
) -> ss_plugin_rc {
    let plugin = plugin as *mut PluginWrapper<T>;
    unsafe {
        let Some(plugin) = plugin.as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(event_input) = event_input.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(extract_input) = extract_input.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        let fields =
            std::slice::from_raw_parts_mut(extract_input.fields, extract_input.num_fields as usize);

        let table_reader = TableReader::new(extract_input.table_reader_ext);
        match plugin.plugin.extract_fields(
            event_input,
            table_reader,
            fields,
            &mut plugin.field_storage,
        ) {
            Ok(()) => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS,
            Err(e) => {
                e.set_last_error(&mut plugin.error_buf);
                e.status_code()
            }
        }
    }
}

#[macro_export]
macro_rules! extract_plugin {
    ($ty:ty) => {
        $crate::wrap_ffi! {
            use $crate::internals::extract::wrappers: <$ty>;

            unsafe fn plugin_get_extract_event_sources() -> *const ::std::ffi::c_char;
            unsafe fn plugin_get_extract_event_types(
                numtypes: *mut u32,
                plugin: *mut falco_plugin_api::ss_plugin_t,
            ) -> *mut u16;
            unsafe fn plugin_get_fields() -> *const ::std::ffi::c_char;
            unsafe fn plugin_extract_fields(
                plugin: *mut falco_plugin_api::ss_plugin_t,
                event_input: *const falco_plugin_api::ss_plugin_event_input,
                extract_input: *const falco_plugin_api::ss_plugin_field_extract_input,
            ) -> i32;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_extract_api() -> falco_plugin_api::plugin_api__bindgen_ty_2 {
            falco_plugin_api::plugin_api__bindgen_ty_2 {
                get_extract_event_sources: Some(plugin_get_extract_event_sources),
                get_extract_event_types: Some(plugin_get_extract_event_types),
                get_fields: Some(plugin_get_fields),
                extract_fields: Some(plugin_extract_fields),
            }
        }
    };
}
