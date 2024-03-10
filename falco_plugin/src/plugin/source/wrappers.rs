use std::ffi::c_char;
use std::io::Write;

use crate::plugin::base::PluginWrapper;
use crate::plugin::error::FfiResult;
use crate::plugin::source::SourcePluginInstanceWrapper;
use crate::source::{SourcePlugin, SourcePluginInstance};
use crate::strings::cstring_writer::WriteIntoCString;
use crate::strings::from_ptr::try_str_from_ptr;
use falco_plugin_api::{
    ss_instance_t, ss_plugin_event, ss_plugin_event_input, ss_plugin_rc,
    ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_t,
};

pub fn plugin_get_event_source<T: SourcePlugin>() -> *const c_char {
    T::EVENT_SOURCE.as_ptr()
}

pub fn plugin_get_id<T: SourcePlugin>() -> u32 {
    T::PLUGIN_ID
}

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_list_open_params<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    rc: *mut i32,
) -> *const c_char {
    let plugin = plugin as *mut PluginWrapper<T>;
    match unsafe { plugin.as_mut() } {
        Some(plugin) => match plugin.plugin.list_open_params() {
            Ok(s) => {
                unsafe {
                    *rc = falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS;
                }
                s.as_ptr()
            }
            Err(e) => {
                unsafe {
                    *rc = e.status_code();
                }
                e.set_last_error(&mut plugin.error_buf);
                std::ptr::null()
            }
        },
        None => std::ptr::null(),
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_open<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    params: *const c_char,
    rc: *mut ss_plugin_rc,
) -> *mut ss_instance_t {
    let plugin = plugin as *mut PluginWrapper<T>;
    unsafe {
        let Some(rc) = rc.as_mut() else {
            return std::ptr::null_mut();
        };

        match plugin.as_mut() {
            Some(plugin) => {
                let params = if params.is_null() {
                    None
                } else {
                    match try_str_from_ptr(params, &()) {
                        Ok(params) => Some(params),
                        Err(e) => {
                            plugin
                                .error_buf
                                .write_into(|w| w.write_all(e.to_string().as_bytes()))
                                .ok();
                            *rc = ss_plugin_rc_SS_PLUGIN_FAILURE;

                            return std::ptr::null_mut();
                        }
                    }
                };

                match plugin.plugin.open(params) {
                    Ok(instance) => {
                        *rc = ss_plugin_rc_SS_PLUGIN_SUCCESS;
                        Box::into_raw(Box::new(SourcePluginInstanceWrapper {
                            instance,
                            batch: Default::default(),
                        }))
                        .cast()
                    }
                    Err(e) => {
                        e.set_last_error(&mut plugin.error_buf);
                        *rc = e.status_code();
                        std::ptr::null_mut()
                    }
                }
            }
            None => {
                *rc = ss_plugin_rc_SS_PLUGIN_FAILURE;
                std::ptr::null_mut()
            }
        }
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_close<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    instance: *mut ss_instance_t,
) {
    let plugin = plugin as *mut PluginWrapper<T>;
    let instance = instance as *mut SourcePluginInstanceWrapper<T::Instance>;
    unsafe {
        if let Some(plugin) = plugin.as_mut() {
            let mut inst = Box::from_raw(instance);
            plugin.plugin.close(&mut inst.instance);
        }
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_next_batch<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    instance: *mut ss_instance_t,
    nevts: *mut u32,
    evts: *mut *mut *mut ss_plugin_event,
) -> ss_plugin_rc {
    let plugin = plugin as *mut PluginWrapper<T>;
    let instance = instance as *mut SourcePluginInstanceWrapper<T::Instance>;
    unsafe {
        let Some(plugin) = plugin.as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(instance) = instance.as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        let mut batch = instance.batch.start();
        match instance.instance.next_batch(&mut plugin.plugin, &mut batch) {
            Ok(()) => {
                let (batch_evts, batch_nevts) = instance.batch.get_raw_pointers();
                *nevts = batch_nevts as u32;
                *evts = batch_evts as *mut *mut _;
                falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS
            }
            Err(e) => {
                e.set_last_error(&mut plugin.error_buf);
                e.status_code()
            }
        }
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_get_progress<T: SourcePlugin>(
    _plugin: *mut ss_plugin_t,
    instance: *mut ss_instance_t,
    progress_pct: *mut u32,
) -> *const c_char {
    let instance = instance as *mut SourcePluginInstanceWrapper<T::Instance>;
    let progress = unsafe { instance.as_mut() }.map(|instance| instance.instance.get_progress());

    if let Some(progress) = progress {
        unsafe {
            *progress_pct = (progress.value * 100.0) as u32;
        }

        match progress.detail {
            Some(s) => s.as_ptr(),
            None => std::ptr::null(),
        }
    } else {
        unsafe {
            *progress_pct = 0;
        }

        std::ptr::null()
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe fn plugin_event_to_string<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    event: *const ss_plugin_event_input,
) -> *const c_char {
    let plugin = plugin as *mut PluginWrapper<T>;
    unsafe {
        let Some(plugin) = plugin.as_mut() else {
            return std::ptr::null_mut();
        };
        let Some(event) = event.as_ref() else {
            return std::ptr::null_mut();
        };

        match plugin
            .plugin
            .event_to_string(event, &mut plugin.string_storage)
        {
            Ok(_) => plugin.string_storage.as_ptr(),
            Err(_) => std::ptr::null(),
        }
    }
}

#[macro_export]
macro_rules! source_plugin {
    ($ty:ty) => {
        $crate::wrap_ffi! {
            use $crate::internals::source::wrappers: <$ty>;
            unsafe fn plugin_next_batch(
                plugin: *mut falco_plugin_api::ss_plugin_t,
                instance: *mut falco_plugin_api::ss_instance_t,
                nevts: *mut u32,
                evts: *mut *mut *mut falco_plugin_api::ss_plugin_event,
            ) -> i32;
            unsafe fn plugin_get_progress(
                plugin: *mut falco_plugin_api::ss_plugin_t,
                instance: *mut falco_plugin_api::ss_instance_t,
                progress_pct: *mut u32,
            ) -> *const ::std::ffi::c_char;
            unsafe fn plugin_get_id() -> u32;
            unsafe fn plugin_get_event_source() -> *const ::std::ffi::c_char;
            unsafe fn plugin_list_open_params(
                plugin: *mut falco_plugin_api::ss_plugin_t,
                rc: *mut i32,
            ) -> *const ::std::ffi::c_char;
            unsafe fn plugin_open(
                plugin: *mut falco_plugin_api::ss_plugin_t,
                params: *const ::std::ffi::c_char,
                rc: *mut i32,
            ) -> *mut falco_plugin_api::ss_instance_t;
            unsafe fn plugin_close(
                plugin: *mut falco_plugin_api::ss_plugin_t,
                instance: *mut falco_plugin_api::ss_instance_t,
            ) -> ();
            unsafe fn plugin_event_to_string(
                plugin: *mut falco_plugin_api::ss_plugin_t,
                event_input: *const falco_plugin_api::ss_plugin_event_input,
            ) -> *const std::ffi::c_char;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_source_api() -> falco_plugin_api::plugin_api__bindgen_ty_1 {
            falco_plugin_api::plugin_api__bindgen_ty_1 {
                next_batch: Some(plugin_next_batch),
                get_progress: Some(plugin_get_progress),
                get_id: Some(plugin_get_id),
                get_event_source: Some(plugin_get_event_source),
                list_open_params: Some(plugin_list_open_params),
                open: Some(plugin_open),
                close: Some(plugin_close),
                event_to_string: Some(plugin_event_to_string),
            }
        }
    };
}
