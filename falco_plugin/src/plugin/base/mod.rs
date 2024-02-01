use crate::extract::FieldStorage;
use crate::plugin::schema::ConfigSchema;
use crate::FailureReason;
use falco_plugin_api::ss_plugin_init_input;
use std::ffi::{CStr, CString};

mod logger;
pub mod wrappers;

// TODO(sdk): convert this into traits?
//       this may make it hard to make the lifetimes line up
//       (will end up with multiple mutable references)
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

pub trait Plugin: Sized {
    const NAME: &'static CStr;
    const PLUGIN_VERSION: &'static CStr;
    const DESCRIPTION: &'static CStr;
    const CONTACT: &'static CStr;

    type ConfigType: ConfigSchema;

    fn new(input: &ss_plugin_init_input, config: Self::ConfigType) -> Result<Self, FailureReason>;
}
