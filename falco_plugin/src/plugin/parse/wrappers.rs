use std::ffi::{c_char, CString};
use std::sync::OnceLock;

use crate::plugin::base::PluginWrapper;
use crate::plugin::error::FfiResult;
use crate::plugin::parse::ParsePlugin;
use falco_plugin_api::{
    ss_plugin_event_input, ss_plugin_event_parse_input, ss_plugin_rc,
    ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_t,
};

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_get_parse_event_types<T: ParsePlugin>(
    numtypes: *mut u32,
    _plugin: *mut ss_plugin_t,
) -> *mut u16 {
    let types = T::EVENT_TYPES;
    if let Some(numtypes) = numtypes.as_mut() {
        *numtypes = types.len() as u32;
        types.as_ptr() as *const u16 as *mut u16 // this should ****really**** be const
    } else {
        std::ptr::null_mut()
    }
}

//noinspection DuplicatedCode
pub fn plugin_get_parse_event_sources<T: ParsePlugin>() -> *const c_char {
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
pub unsafe fn plugin_parse_event<T: ParsePlugin>(
    plugin: *mut ss_plugin_t,
    event: *const ss_plugin_event_input,
    parse_input: *const ss_plugin_event_parse_input,
) -> ss_plugin_rc {
    let plugin = plugin as *mut PluginWrapper<T>;
    unsafe {
        let Some(plugin) = plugin.as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(event) = event.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(parse_input) = parse_input.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        match plugin.plugin.parse_event(event, parse_input) {
            Ok(()) => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS,
            Err(e) => {
                e.set_last_error(&mut plugin.error_buf);
                e.status_code()
            }
        }
    }
}

#[macro_export]
macro_rules! parse_plugin {
    ($ty:ty) => {
        $crate::wrap_ffi! {
            use $crate::internals::parse::wrappers: <$ty>;

            unsafe fn plugin_get_parse_event_types(
                numtypes: *mut u32,
                plugin: *mut falco_plugin_api::ss_plugin_t,
            ) -> *mut u16;
            unsafe fn plugin_get_parse_event_sources() -> *const ::std::ffi::c_char;
            unsafe fn plugin_parse_event(
                plugin: *mut falco_plugin_api::ss_plugin_t,
                event_input: *const falco_plugin_api::ss_plugin_event_input,
                parse_input: *const falco_plugin_api::ss_plugin_event_parse_input,
            ) -> i32;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_parse_api() -> falco_plugin_api::plugin_api__bindgen_ty_3 {
            falco_plugin_api::plugin_api__bindgen_ty_3 {
                get_parse_event_types: Some(plugin_get_parse_event_types),
                get_parse_event_sources: Some(plugin_get_parse_event_sources),
                parse_event: Some(plugin_parse_event),
            }
        }
    };
}
