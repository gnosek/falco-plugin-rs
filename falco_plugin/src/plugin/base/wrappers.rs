use anyhow::Context;
use falco_plugin_api::{
    ss_plugin_init_input, ss_plugin_metric, ss_plugin_rc, ss_plugin_rc_SS_PLUGIN_FAILURE,
    ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_t,
};
use std::collections::BTreeMap;
use std::ffi::{c_char, CString};
use std::sync::Mutex;

use crate::base::Plugin;
use crate::plugin::base::logger::FalcoPluginLogger;
use crate::plugin::base::PluginWrapper;
use crate::plugin::error::ffi_result::FfiResult;
use crate::plugin::schema::{ConfigSchema, ConfigSchemaType};
use crate::strings::from_ptr::try_str_from_ptr;

pub extern "C" fn plugin_get_required_api_version<
    const MAJOR: usize,
    const MINOR: usize,
    const PATCH: usize,
>() -> *const c_char {
    static VERSIONS: Mutex<BTreeMap<(usize, usize, usize), CString>> = Mutex::new(BTreeMap::new());

    let mut version = VERSIONS.lock().unwrap();
    // we only generate the string once and never change or delete it
    // so the pointer should remain valid for the static lifetime
    version
        .entry((MAJOR, MINOR, PATCH))
        .or_insert_with(|| {
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
    rc: *mut ss_plugin_rc,
) -> *mut falco_plugin_api::ss_plugin_t {
    let res = (|| -> Result<*mut PluginWrapper<P>, anyhow::Error> {
        let init_input =
            unsafe { init_input.as_ref() }.ok_or(anyhow::anyhow!("Got empty init_input"))?;

        let init_config = try_str_from_ptr(init_input.config, &init_input)
            .context("Failed to get config string")?;

        let config = P::ConfigType::from_str(init_config).context("Failed to parse config")?;
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
            let error_str = format!("{:#}", &e);
            log::error!("Failed to initialize plugin: {}", error_str);
            let plugin = Box::new(PluginWrapper::<P>::new_error(error_str));
            *rc = e.status_code();
            Box::into_raw(plugin).cast()
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

    let Some(ref mut actual_plugin) = &mut plugin.plugin else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    let res = (|| -> Result<(), anyhow::Error> {
        let config_input = unsafe { config_input.as_ref() }.context("Got NULL config")?;

        let updated_config = try_str_from_ptr(config_input.config, &config_input)
            .context("Failed to get config string")?;
        let config = P::ConfigType::from_str(updated_config).context("Failed to parse config")?;

        actual_plugin.set_config(config)
    })();

    res.rc(&mut plugin.error_buf)
}

pub unsafe extern "C" fn plugin_get_metrics<P: Plugin>(
    plugin: *mut ss_plugin_t,
    num_metrics: *mut u32,
) -> *mut ss_plugin_metric {
    let plugin = plugin as *mut PluginWrapper<P>;
    let Some(plugin) = plugin.as_mut() else {
        *num_metrics = 0;
        return std::ptr::null_mut();
    };
    let Some(ref mut actual_plugin) = &mut plugin.plugin else {
        *num_metrics = 0;
        return std::ptr::null_mut();
    };
    let Some(num_metrics) = num_metrics.as_mut() else {
        *num_metrics = 0;
        return std::ptr::null_mut();
    };

    plugin.metric_storage.clear();
    for metric in actual_plugin.get_metrics() {
        plugin.metric_storage.push(metric.as_raw());
    }

    *num_metrics = plugin.metric_storage.len() as u32;
    plugin.metric_storage.as_ptr().cast_mut()
}

#[doc(hidden)]
#[macro_export]
macro_rules! wrap_ffi {
    (
        #[$attr:meta]
        use $mod:path: <$ty:ty>;

    $(unsafe fn $name:ident( $($param:ident: $param_ty:ty),* $(,)*) -> $ret:ty;)*
    ) => {
        $(
        #[$attr]
        pub unsafe extern "C" fn $name ( $($param: $param_ty),*) -> $ret {
            use $mod as wrappers;

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
/// use falco_plugin::base::Plugin;
/// # use falco_plugin::base::Metric;
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
/// #        -> Result<Self, anyhow::Error> {
/// #        Ok(MyPlugin)
/// #    }
/// #
/// #    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
/// #        Ok(())
/// #    }
/// #
/// #    fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
/// #        []
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
/// use falco_plugin::base::Plugin;
/// # use falco_plugin::base::Metric;
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
/// #        -> Result<Self, anyhow::Error> {
/// #        Ok(MyPlugin)
/// #    }
/// #
/// #    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
/// #        Ok(())
/// #    }
/// #
/// #    fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
/// #        []
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
        $crate::base_plugin_ffi_wrappers!($maj; $min; $patch => #[no_mangle] $ty);
    };
}

/// # Automatically generate the Falco plugin API structure for static plugins
///
// TODO actually document
/// **Note**: this does not affect the actual version supported in any way. If you use this form,
/// it's **entirely your responsibility** to ensure the advertised version is compatible with the actual
/// version supported by this crate.
#[macro_export]
macro_rules! static_plugin {
    ($name:ident = $ty:ty) => {
        static_plugin!(
            $name @ (
            falco_plugin::api::PLUGIN_API_VERSION_MAJOR as usize;
            falco_plugin::api::PLUGIN_API_VERSION_MINOR as usize;
            0)
            = $ty
        );

    };
    ($name:ident @ ($maj:expr; $min:expr; $patch:expr) = $ty:ty) => {
        #[no_mangle]
        static $name: falco_plugin::api::plugin_api = const {
            $crate::base_plugin_ffi_wrappers!($maj; $min; $patch => #[deny(dead_code)] $ty);
            __plugin_base_api()
        };
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! base_plugin_ffi_wrappers {
    ($maj:expr; $min:expr; $patch:expr => #[$attr:meta] $ty:ty) => {
        #[$attr]
        pub extern "C" fn plugin_get_required_api_version() -> *const std::ffi::c_char {
            $crate::internals::base::wrappers::plugin_get_required_api_version::<
                { $maj },
                { $min },
                { $patch },
            >()
        }

        $crate::wrap_ffi! {
            #[$attr]
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
            unsafe fn plugin_get_metrics(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                num_metrics: *mut u32,
            ) -> *mut falco_plugin::api::ss_plugin_metric;
        }

        #[allow(dead_code)]
        pub const fn __plugin_base_api() -> falco_plugin::api::plugin_api {
            use $crate::internals::async_events::wrappers::AsyncPluginFallbackApi;
            use $crate::internals::extract::wrappers::ExtractPluginFallbackApi;
            use $crate::internals::parse::wrappers::ParsePluginFallbackApi;
            use $crate::internals::source::wrappers::SourcePluginFallbackApi;
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
                __bindgen_anon_1:
                    $crate::internals::source::wrappers::SourcePluginApi::<$ty>::SOURCE_API,
                __bindgen_anon_2:
                    $crate::internals::extract::wrappers::ExtractPluginApi::<$ty>::EXTRACT_API,
                __bindgen_anon_3:
                    $crate::internals::parse::wrappers::ParsePluginApi::<$ty>::PARSE_API,
                __bindgen_anon_4:
                    $crate::internals::async_events::wrappers::AsyncPluginApi::<$ty>::ASYNC_API,
                set_config: Some(plugin_set_config),
                get_metrics: Some(plugin_get_metrics),
            }
        }
    };
}
