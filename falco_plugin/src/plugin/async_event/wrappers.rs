use crate::plugin::async_event::async_handler::AsyncHandler;
use crate::plugin::async_event::AsyncEventPlugin;
use crate::plugin::base::PluginWrapper;
use crate::plugin::error::FfiResult;
use falco_plugin_api::{
    ss_plugin_async_event_handler_t, ss_plugin_owner_t, ss_plugin_rc,
    ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_t,
};
use std::ffi::{c_char, CString};
use std::sync::OnceLock;

//noinspection DuplicatedCode
pub fn plugin_get_async_event_sources<T: AsyncEventPlugin>() -> *const c_char {
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

//noinspection DuplicatedCode
pub fn plugin_get_async_events<T: AsyncEventPlugin>() -> *const c_char {
    static EVENTS: OnceLock<CString> = OnceLock::new();
    if EVENTS.get().is_none() {
        let sources =
            serde_json::to_string(T::ASYNC_EVENTS).expect("failed to serialize event name array");
        let sources =
            CString::new(sources.into_bytes()).expect("failed to add NUL to event name array");
        EVENTS
            .set(sources)
            .expect("multiple plugins not supported in a single crate");
    }

    EVENTS.get().unwrap().as_ptr()
}

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_set_async_event_handler<T: AsyncEventPlugin>(
    plugin: *mut ss_plugin_t,
    owner: *mut ss_plugin_owner_t,
    handler: ss_plugin_async_event_handler_t,
) -> ss_plugin_rc {
    unsafe {
        let Some(plugin) = (plugin as *mut PluginWrapper<T>).as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        if let Err(e) = plugin.plugin.stop_async() {
            e.set_last_error(&mut plugin.error_buf);
            return e.status_code();
        }

        let Some(raw_handler) = handler.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_SUCCESS;
        };

        let handler = AsyncHandler {
            owner,
            raw_handler: *raw_handler,
        };
        if let Err(e) = plugin.plugin.start_async(handler) {
            e.set_last_error(&mut plugin.error_buf);
            return e.status_code();
        }

        ss_plugin_rc_SS_PLUGIN_SUCCESS
    }
}

#[macro_export]
macro_rules! async_event_plugin {
    ($ty:ty) => {
        $crate::wrap_ffi! {
            use $crate::internals::async_events::wrappers: <$ty>;

            unsafe fn plugin_get_async_events() -> *const ::std::ffi::c_char;
            unsafe fn plugin_get_async_event_sources() -> *const ::std::ffi::c_char;
            unsafe fn plugin_set_async_event_handler(
                plugin: *mut falco_plugin_api::ss_plugin_t,
                owner: *mut falco_plugin_api::ss_plugin_owner_t,
                handler: falco_plugin_api::ss_plugin_async_event_handler_t,
            ) -> falco_plugin_api::ss_plugin_rc;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_parse_api() -> falco_plugin_api::plugin_api__bindgen_ty_4 {
            falco_plugin_api::plugin_api__bindgen_ty_4 {
                get_async_event_sources: Some(plugin_get_async_event_sources),
                get_async_events: Some(plugin_get_async_events),
                set_async_event_handler: Some(plugin_set_async_event_handler),
            }
        }
    };
}
