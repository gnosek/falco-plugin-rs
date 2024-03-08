use crate::base::InitInput;
use crate::extract::FieldStorage;
use crate::plugin::schema::ConfigSchema;
use crate::FailureReason;
use std::ffi::{CStr, CString};

mod logger;
#[doc(hidden)]
pub mod wrappers;

// TODO(sdk): convert this into traits?
//       this may make it hard to make the lifetimes line up
//       (will end up with multiple mutable references)
#[doc(hidden)]
pub struct PluginWrapper<P: Plugin> {
    pub(crate) plugin: P,
    pub(crate) error_buf: CString,
    pub(crate) field_storage: FieldStorage,
    pub(crate) string_storage: CString,
}

impl<P: Plugin> PluginWrapper<P> {
    pub fn new(plugin: P) -> Self {
        Self {
            plugin,
            error_buf: Default::default(),
            field_storage: Default::default(),
            string_storage: Default::default(),
        }
    }
}

/// # A base trait for implementing Falco plugins
///
/// There are several constants you need to set to describe the metadata for your plugin, described
/// below. All the constants are C-style strings. In Rust versions below 1.77, you can use
/// the [`c!`](`crate::c`) macro to construct them. Since 1.77, native C strings (`c"sample-plugin-rs"`)
/// are a much better alternative.
pub trait Plugin: Sized {
    /// the name of your plugin, must match the plugin name in the Falco config file
    const NAME: &'static CStr;
    /// the version of your plugin
    const PLUGIN_VERSION: &'static CStr;
    /// a free-form description of what your plugin does
    const DESCRIPTION: &'static CStr;
    /// a way to contact you with issues regarding the plugin, be it email or a website
    const CONTACT: &'static CStr;

    /// The plugin can be configured in three different ways. In all cases, an instance of the type
    /// you specify will be passed to the [`Plugin::new`] method.
    ///
    /// See <https://falco.org/docs/plugins/usage/> for more information about plugin configuration
    /// in Falco.
    ///
    /// ### No configuration
    ///
    /// If your plugin does not need any configuration, set the `ConfigType` to an empty tuple.
    ///
    /// ### Configuration as a string
    ///
    /// If you set the `ConfigType` to [`String`], your plugin will receive the configuration
    /// as a string, read directly from the Falco config file.
    ///
    /// ### Configuration as JSON
    ///
    /// Plugins can also be configured using a JSON object. This will be parsed by the SDK and your
    /// plugin will receive a data structure containing all the parsed fields. In order to use JSON
    /// configuration, set the `ConfigType` to `Json<T>`, where the [`Json`](`crate::base::Json`)
    /// type is provided by this crate and the type `T` must implement [`serde::de::DeserializeOwned`].
    ///
    /// Please note that you can use the reexport (`falco_plugin::serde`) to ensure you're using
    /// the same version of serde as the SDK.
    type ConfigType: ConfigSchema;

    /// This is the only required method. It takes a plugin init input instance (its only notable
    /// feature is that it supports the [`TableInitInput`](`crate::base::TableInitInput`) trait,
    /// which lets you access tables exposed by other plugins (and Falco core).
    fn new(input: &InitInput, config: Self::ConfigType) -> Result<Self, FailureReason>;
}
