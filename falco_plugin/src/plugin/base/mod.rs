use falco_plugin_api::ss_plugin_metric;
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::io::Write;

use crate::base::InitInput;
use crate::extract::FieldStorage;
use crate::plugin::base::metrics::Metric;
use crate::plugin::schema::ConfigSchema;
use crate::strings::cstring_writer::WriteIntoCString;

mod logger;
pub mod metrics;
#[doc(hidden)]
pub mod wrappers;

// TODO(sdk): convert this into traits?
//       this may make it hard to make the lifetimes line up
//       (will end up with multiple mutable references)
#[doc(hidden)]
pub struct PluginWrapper<P: Plugin> {
    pub(crate) plugin: Option<P>,
    pub(crate) error_buf: CString,
    pub(crate) field_storage: FieldStorage,
    pub(crate) string_storage: CString,
    pub(crate) metric_storage: Vec<ss_plugin_metric>,
}

impl<P: Plugin> PluginWrapper<P> {
    pub fn new(plugin: P) -> Self {
        Self {
            plugin: Some(plugin),
            error_buf: Default::default(),
            field_storage: Default::default(),
            string_storage: Default::default(),
            metric_storage: Default::default(),
        }
    }

    pub fn new_error(err: impl Display) -> Self {
        let mut plugin = Self {
            plugin: None,
            error_buf: Default::default(),
            field_storage: Default::default(),
            string_storage: Default::default(),
            metric_storage: vec![],
        };

        plugin
            .error_buf
            .write_into(|buf| write!(buf, "{}", err))
            .unwrap_or_else(|err| panic!("Failed to write error message (was: {})", err));

        plugin
    }
}

/// # A base trait for implementing Falco plugins
///
/// There are several constants you need to set to describe the metadata for your plugin, described
/// below. All the constants are C-style strings: you can initialize the fields with `c"foo"`.
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

    /// This method takes a plugin init input instance, whose only notable feature is that it supports
    /// the [`TableInitInput`](`crate::base::TableInitInput`) trait, which lets you access tables
    /// exposed by other plugins (and Falco core).
    ///
    /// It should return a new instance of `Self`
    fn new(input: &InitInput, config: Self::ConfigType) -> Result<Self, anyhow::Error>;

    /// Update the configuration of a running plugin
    ///
    /// The default implementation does nothing
    fn set_config(&mut self, _config: Self::ConfigType) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// Return the plugin metrics
    fn get_metrics(&mut self) -> impl IntoIterator<Item = Metric> {
        []
    }
}
