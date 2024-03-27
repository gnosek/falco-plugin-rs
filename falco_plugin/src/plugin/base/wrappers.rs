use std::ffi::{c_char, CString};
use std::sync::OnceLock;

use falco_plugin_api::{
    ss_plugin_init_input, ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_SUCCESS,
};

use crate::base::Plugin;
use crate::internals::async_events::wrappers::AsyncPluginApi;
use crate::internals::async_events::wrappers::AsyncPluginFallbackApi;
use crate::internals::extract::wrappers::ExtractPluginApi;
use crate::internals::extract::wrappers::ExtractPluginFallbackApi;
use crate::internals::parse::wrappers::ParsePluginApi;
use crate::internals::parse::wrappers::ParsePluginFallbackApi;
use crate::internals::source::wrappers::SourcePluginApi;
use crate::internals::source::wrappers::SourcePluginFallbackApi;
use crate::plugin::base::logger::FalcoPluginLogger;
use crate::plugin::base::PluginWrapper;
use crate::plugin::error::FfiResult;
use crate::plugin::schema::{ConfigSchema, ConfigSchemaType};
use crate::strings::from_ptr::try_str_from_ptr;
use crate::FailureReason;

/// # Automatically generate the Falco plugin API structure (overriding the API version)
///
/// **Note**: you probably want [`PluginApi`], which picks the current API version automatically
///
/// For any type `T` that implements [`Plugin`], you can find the [`falco_plugin_api::plugin_api`]
/// struct corresponding to this plugin and advertising X.Y.Z as the API version
/// at `PluginApiWithVersionOverride<X, Y, Z, T>::PLUGIN_API`.
///
/// **Note**: this does not affect the actual version supported in any way. If you use this form,
/// it's **entirely your responsibility** to ensure the advertised version is compatible with the actual
/// version supported by this crate.
pub struct PluginApiWithVersionOverride<
    const MAJOR: usize,
    const MINOR: usize,
    const PATCH: usize,
    T,
>(std::marker::PhantomData<T>);

impl<T: Plugin, const MAJOR: usize, const MINOR: usize, const PATCH: usize>
    PluginApiWithVersionOverride<MAJOR, MINOR, PATCH, T>
{
    pub const PLUGIN_API: falco_plugin_api::plugin_api = falco_plugin_api::plugin_api {
        get_required_api_version: Some(plugin_get_required_api_version::<MAJOR, MINOR, PATCH>),
        get_init_schema: Some(plugin_get_init_schema::<T>),
        init: Some(plugin_init::<T>),
        destroy: Some(plugin_destroy::<T>),
        get_last_error: Some(plugin_get_last_error::<T>),
        get_name: Some(plugin_get_name::<T>),
        get_description: Some(plugin_get_description::<T>),
        get_contact: Some(plugin_get_contact::<T>),
        get_version: Some(plugin_get_version::<T>),
        __bindgen_anon_1: SourcePluginApi::<T>::SOURCE_API,
        __bindgen_anon_2: ExtractPluginApi::<T>::EXTRACT_API,
        __bindgen_anon_3: ParsePluginApi::<T>::PARSE_API,
        __bindgen_anon_4: AsyncPluginApi::<T>::ASYNC_API,
        set_config: Some(plugin_set_config::<T>),
    };
}

/// # Automatically generate the Falco plugin API structure
///
/// For any type `T` that implements [`Plugin`], you can find the [`falco_plugin_api::plugin_api`]
/// struct corresponding to this plugin at `PluginApi<T>::PLUGIN_API`.
pub type PluginApi<T> = PluginApiWithVersionOverride<
    { falco_plugin_api::PLUGIN_API_VERSION_MAJOR as usize },
    { falco_plugin_api::PLUGIN_API_VERSION_MINOR as usize },
    0usize,
    T,
>;

pub extern "C" fn plugin_get_required_api_version<
    const MAJOR: usize,
    const MINOR: usize,
    const PATCH: usize,
>() -> *const c_char {
    static REQUIRED_API_VERSION: OnceLock<CString> = OnceLock::new();
    REQUIRED_API_VERSION
        .get_or_init(|| {
            let version = format!("{}.{}.{}", MAJOR, MINOR, PATCH);
            CString::new(version).unwrap()
        })
        .as_ptr()
}

pub extern "C" fn plugin_get_version<T: Plugin>() -> *const c_char {
    T::PLUGIN_VERSION.as_ptr()
}

pub extern "C" fn plugin_get_name<T: Plugin>() -> *const c_char {
    T::NAME.as_ptr()
}

pub extern "C" fn plugin_get_description<T: Plugin>() -> *const c_char {
    T::DESCRIPTION.as_ptr()
}

pub extern "C" fn plugin_get_contact<T: Plugin>() -> *const c_char {
    T::CONTACT.as_ptr()
}

/// # Safety
///
/// init_input must be null or a valid pointer
pub unsafe extern "C" fn plugin_init<P: Plugin>(
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
pub unsafe extern "C" fn plugin_get_init_schema<P: Plugin>(
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
pub unsafe extern "C" fn plugin_destroy<P: Plugin>(plugin: *mut falco_plugin_api::ss_plugin_t) {
    unsafe {
        let plugin = plugin as *mut PluginWrapper<P>;
        let _ = Box::from_raw(plugin);
    }
}

/// # Safety
///
/// `plugin` must be a valid pointer to `PluginWrapper<P>`
pub unsafe extern "C" fn plugin_get_last_error<P: Plugin>(
    plugin: *mut falco_plugin_api::ss_plugin_t,
) -> *const c_char {
    let plugin = plugin as *mut PluginWrapper<P>;
    match unsafe { plugin.as_mut() } {
        Some(plugin) => plugin.error_buf.as_ptr(),
        None => c"no instance".as_ptr(),
    }
}

pub unsafe extern "C" fn plugin_set_config<P: Plugin>(
    plugin: *mut falco_plugin_api::ss_plugin_t,
    config_input: *const falco_plugin_api::ss_plugin_set_config_input,
) -> falco_plugin_api::ss_plugin_rc {
    let plugin = plugin as *mut PluginWrapper<P>;
    let Some(plugin) = plugin.as_mut() else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    let res = (|| -> Result<(), anyhow::Error> {
        let config_input = unsafe { config_input.as_ref() }.ok_or(FailureReason::Failure)?;

        let updated_config = try_str_from_ptr(config_input.config, &config_input)
            .map_err(|_| FailureReason::Failure)?;
        let config = P::ConfigType::from_str(updated_config).map_err(|_| FailureReason::Failure)?;

        plugin.plugin.set_config(config)
    })();

    match res {
        Ok(()) => ss_plugin_rc_SS_PLUGIN_SUCCESS,
        Err(e) => {
            e.set_last_error(&mut plugin.error_buf);
            e.status_code()
        }
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
/// with a type implementing [`Plugin`] as the sole parameter:
///
/// ```
/// # use std::ffi::CStr;
/// # use falco_plugin::base::InitInput;
/// # use falco_plugin::FailureReason;
/// use falco_plugin::base::Plugin;
/// use falco_plugin::plugin;
///
/// struct MyPlugin;
/// impl Plugin for MyPlugin {
///     // ...
/// #    const NAME: &'static CStr = c"sample-plugin-rs";
/// #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
/// #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
/// #    const CONTACT: &'static CStr = c"you@example.com";
/// #    type ConfigType = ();
/// #
/// #    fn new(input: &InitInput, config: Self::ConfigType)
/// #        -> Result<Self, FailureReason> {
/// #        Ok(MyPlugin)
/// #    }
/// #
/// #    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
/// #        Ok(())
/// #    }
/// }
///
/// plugin!(MyPlugin);
/// ```
///
/// It implements a form where you can override the required API version (for example, if
/// you wish to advertise an older version for increased compatibility):
///
/// ```
/// # use std::ffi::CStr;
/// # use falco_plugin::base::InitInput;
/// # use falco_plugin::FailureReason;
/// use falco_plugin::base::Plugin;
/// use falco_plugin::plugin;
///
/// struct MyPlugin;
/// impl Plugin for MyPlugin {
///     // ...
/// #    const NAME: &'static CStr = c"sample-plugin-rs";
/// #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
/// #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
/// #    const CONTACT: &'static CStr = c"you@example.com";
/// #    type ConfigType = ();
/// #
/// #    fn new(input: &InitInput, config: Self::ConfigType)
/// #        -> Result<Self, FailureReason> {
/// #        Ok(MyPlugin)
/// #    }
/// #
/// #    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
/// #        Ok(())
/// #    }
/// }
///
/// // require version 3.3.0 of the API
/// plugin!(3;3;0 => MyPlugin);
/// ```
///
/// **Note**: this does not affect the actual version supported in any way. If you use this form,
/// it's **entirely your responsibility** to ensure the advertised version is compatible with the actual
/// version supported by this crate.
#[macro_export]
macro_rules! plugin {
    ($ty:ty) => {
        plugin!(
            falco_plugin::api::PLUGIN_API_VERSION_MAJOR as usize;
            falco_plugin::api::PLUGIN_API_VERSION_MINOR as usize;
            0 => $ty
        );
    };
    ($maj:expr; $min:expr; $patch:expr => $ty:ty) => {
        #[no_mangle]
        pub extern "C" fn plugin_get_required_api_version() -> *const std::ffi::c_char {
            $crate::internals::base::wrappers::plugin_get_required_api_version::<{$maj}, {$min}, {$patch}>()
        }

        $crate::wrap_ffi! {
            use $crate::internals::base::wrappers: <$ty>;

            unsafe fn plugin_get_version() -> *const std::ffi::c_char;
            unsafe fn plugin_get_name() -> *const std::ffi::c_char;
            unsafe fn plugin_get_description() -> *const std::ffi::c_char;
            unsafe fn plugin_get_contact() -> *const std::ffi::c_char;
            unsafe fn plugin_get_init_schema(schema_type: *mut u32) -> *const std::ffi::c_char;
            unsafe fn plugin_init(
                args: *const falco_plugin::api::ss_plugin_init_input,
                rc: *mut i32,
            ) -> *mut falco_plugin::api::ss_plugin_t;
            unsafe fn plugin_destroy(plugin: *mut falco_plugin::api::ss_plugin_t) -> ();
            unsafe fn plugin_get_last_error(
                plugin: *mut falco_plugin::api::ss_plugin_t,
            ) -> *const std::ffi::c_char;
            unsafe fn plugin_set_config(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                config_input: *const falco_plugin::api::ss_plugin_set_config_input,
            ) -> falco_plugin::api::ss_plugin_rc;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_base_api() -> falco_plugin::api::plugin_api {
            use $crate::internals::source::wrappers::SourcePluginFallbackApi;
            use $crate::internals::extract::wrappers::ExtractPluginFallbackApi;
            use $crate::internals::parse::wrappers::ParsePluginFallbackApi;
            use $crate::internals::async_events::wrappers::AsyncPluginFallbackApi;
            falco_plugin::api::plugin_api {
                get_required_api_version: Some(plugin_get_required_api_version),
                get_version: Some(plugin_get_version),
                get_name: Some(plugin_get_name),
                get_description: Some(plugin_get_description),
                get_contact: Some(plugin_get_contact),
                get_init_schema: Some(plugin_get_init_schema),
                init: Some(plugin_init),
                destroy: Some(plugin_destroy),
                get_last_error: Some(plugin_get_last_error),
                __bindgen_anon_1: $crate::internals::source::wrappers::SourcePluginApi::<$ty>::SOURCE_API,
                __bindgen_anon_2: $crate::internals::extract::wrappers::ExtractPluginApi::<$ty>::EXTRACT_API,
                __bindgen_anon_3: $crate::internals::parse::wrappers::ParsePluginApi::<$ty>::PARSE_API,
                __bindgen_anon_4: $crate::internals::async_events::wrappers::AsyncPluginApi::<$ty>::ASYNC_API,
                set_config: Some(plugin_set_config),
            }
        }
    };
}
