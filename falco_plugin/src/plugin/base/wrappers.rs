use std::ffi::c_char;

use falco_plugin_api::{ss_plugin_init_input, ss_plugin_rc_SS_PLUGIN_SUCCESS};

use crate::base::Plugin;
use crate::plugin::base::logger::FalcoPluginLogger;
use crate::plugin::base::PluginWrapper;
use crate::plugin::schema::{ConfigSchema, ConfigSchemaType};
use crate::strings::from_ptr::try_str_from_ptr;
use crate::{c, FailureReason};

pub fn plugin_get_version<T: Plugin>() -> *const c_char {
    T::PLUGIN_VERSION.as_ptr()
}

pub fn plugin_get_name<T: Plugin>() -> *const c_char {
    T::NAME.as_ptr()
}

pub fn plugin_get_description<T: Plugin>() -> *const c_char {
    T::DESCRIPTION.as_ptr()
}

pub fn plugin_get_contact<T: Plugin>() -> *const c_char {
    T::CONTACT.as_ptr()
}

/// # Safety
///
/// init_input must be null or a valid pointer
pub unsafe fn plugin_init<P: Plugin>(
    init_input: *const ss_plugin_init_input,
    rc: *mut i32,
) -> *mut falco_plugin_api::ss_plugin_t {
    let res = (|| -> Result<*mut PluginWrapper<P>, FailureReason> {
        let init_input = unsafe { init_input.as_ref() }.ok_or(FailureReason::Failure)?;

        let init_config =
            try_str_from_ptr(init_input.config, &init_input).map_err(|_| FailureReason::Failure)?;
        let config = P::ConfigType::from_str(init_config).map_err(|_| FailureReason::Failure)?;

        if let Some(log_fn) = init_input.log_fn {
            let logger = Box::new(FalcoPluginLogger {
                owner: init_input.owner,
                logger_fn: log_fn,
            });
            log::set_boxed_logger(logger).ok();
        }

        P::new(init_input, config).map(|plugin| Box::into_raw(Box::new(PluginWrapper::new(plugin))))
    })();

    match res {
        Ok(plugin) => {
            *rc = ss_plugin_rc_SS_PLUGIN_SUCCESS;
            plugin.cast()
        }
        Err(e) => {
            *rc = e as i32;
            std::ptr::null_mut()
        }
    }
}

/// # Safety
///
/// schema_type must be null or a valid pointer
pub unsafe fn plugin_get_init_schema<P: Plugin>(
    schema_type: *mut falco_plugin_api::ss_plugin_schema_type,
) -> *const c_char {
    let Some(schema_type) = schema_type.as_mut() else {
        return std::ptr::null();
    };
    match P::ConfigType::get_schema() {
        ConfigSchemaType::None => {
            *schema_type = falco_plugin_api::ss_plugin_schema_type_SS_PLUGIN_SCHEMA_NONE;
            std::ptr::null()
        }
        ConfigSchemaType::Json(s) => {
            *schema_type = falco_plugin_api::ss_plugin_schema_type_SS_PLUGIN_SCHEMA_JSON;
            s.as_ptr()
        }
    }
}

/// # Safety
///
/// `plugin` must have been created by `init()` and not destroyed since
pub unsafe fn plugin_destroy<P: Plugin>(plugin: *mut falco_plugin_api::ss_plugin_t) {
    unsafe {
        let plugin = plugin as *mut PluginWrapper<P>;
        let _ = Box::from_raw(plugin);
    }
}

/// # Safety
///
/// `plugin` must be a valid pointer to `PluginWrapper<P>`
pub unsafe fn plugin_get_last_error<P: Plugin>(
    plugin: *mut falco_plugin_api::ss_plugin_t,
) -> *const c_char {
    let plugin = plugin as *mut PluginWrapper<P>;
    match unsafe { plugin.as_mut() } {
        Some(plugin) => plugin.error_buf.as_ptr(),
        None => c!("no instance").as_ptr(),
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! wrap_ffi {
    (use $mod:path: <$ty:ty>;

    $(unsafe fn $name:ident( $($param:ident: $param_ty:ty),* $(,)*) -> $ret:ty;)*
    ) => {
        $(
        #[no_mangle]
        pub unsafe extern "C" fn $name ( $($param: $param_ty),*) -> $ret {
            use $mod as wrappers;

            // In release builds, catch all panics to maintain the ABI
            // (unwinding across FFI boundaries is undefined behavior)
            #[cfg(not(debug_assertions))]
            match std::panic::catch_unwind(|| wrappers::$name::<$ty>($($param),*)) {
                Ok(ret) => ret,
                Err(_) => std::process::abort(),
            }

            // In debug builds, do not interrupt unwinding. This is technically UB,
            // but seems to work in practice (famous last words). More importantly,
            // it allows easier debugging (it seems it's hard to single-step into
            // the closure passed to catch_unwind as it ends up being called from
            // a compiler built-in function we cannot single-step through)
            #[cfg(debug_assertions)]
            wrappers::$name::<$ty>($($param),*)
        }
        )*
    }
}

/// # Register a Falco plugin
///
/// This macro must be called at most once in a crate (it generates public functions)
/// with a type implementing [`Plugin`] as the sole parameter.
#[macro_export]
macro_rules! plugin {
    ($ty:ty) => {
        #[no_mangle]
        pub extern "C" fn plugin_get_required_api_version() -> *const std::ffi::c_char {
            $crate::c!("3.3.0").as_ptr()
            /*
            // SAFETY: we have exactly one trailing NUL
            unsafe {
                ::std::ffi::CStr::from_bytes_with_nul_unchecked(
                    const_format::concatcp!(
                        falco_plugin_api::PLUGIN_API_VERSION_MAJOR,
                        ".",
                        falco_plugin_api::PLUGIN_API_VERSION_MINOR,
                        ".",
                        falco_plugin_api::PLUGIN_API_VERSION_PATCH,
                        "\0",
                    )
                    .as_bytes(),
                )
                .as_ptr()
            }*/
        }

        $crate::wrap_ffi! {
            use $crate::internals::base::wrappers: <$ty>;

            unsafe fn plugin_get_version() -> *const std::ffi::c_char;
            unsafe fn plugin_get_name() -> *const std::ffi::c_char;
            unsafe fn plugin_get_description() -> *const std::ffi::c_char;
            unsafe fn plugin_get_contact() -> *const std::ffi::c_char;
            unsafe fn plugin_get_init_schema(schema_type: *mut u32) -> *const std::ffi::c_char;
            unsafe fn plugin_init(
                args: *const falco_plugin_api::ss_plugin_init_input,
                rc: *mut i32,
            ) -> *mut falco_plugin_api::ss_plugin_t;
            unsafe fn plugin_destroy(plugin: *mut falco_plugin_api::ss_plugin_t) -> ();
            unsafe fn plugin_get_last_error(
                plugin: *mut falco_plugin_api::ss_plugin_t,
            ) -> *const std::ffi::c_char;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_base_api(api: &mut falco_plugin_api::plugin_api) {
            api.get_required_api_version = Some(plugin_get_required_api_version);
            api.get_version = Some(plugin_get_version);
            api.get_name = Some(plugin_get_name);
            api.get_description = Some(plugin_get_description);
            api.get_contact = Some(plugin_get_contact);
            api.get_init_schema = Some(plugin_get_init_schema);
            api.init = Some(plugin_init);
            api.destroy = Some(plugin_destroy);
            api.get_last_error = Some(plugin_get_last_error);
        }
    };
}
