//! # A collection of tests for [`falco_plugin`]
//!
//! This crate isn't really intended for public use, except maybe as a collection of sample plugins.

#[cfg(have_libsinsp)]
mod ffi;

use anyhow::Context;
#[cfg(have_libsinsp)]
pub use ffi::*;
use std::ffi::CStr;

#[cfg(not(have_libsinsp))]
mod fallback;

#[cfg(not(have_libsinsp))]
pub use fallback::*;

pub mod common;
pub use common::*;

pub fn init_plugin(
    api: falco_plugin::api::plugin_api,
    config: &CStr,
) -> anyhow::Result<(SinspTestDriver<CaptureNotStarted>, SinspPlugin)> {
    let mut driver = new_test_driver()?;
    let plugin = driver.register_plugin(&Api(api), config)?;

    Ok((driver, plugin))
}

impl SinspTestDriver<CaptureStarted> {
    pub fn next_event_as_str(&mut self) -> anyhow::Result<Option<String>> {
        let event = match self.next_event() {
            Ok(event) => event,
            Err(e) => return Err(anyhow::anyhow!("{:?}", e)).context(e),
        };
        self.event_field_as_string(c"evt.plugininfo", &event)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn compile_test() {
        let _ = super::new_test_driver();
    }

    #[test]
    fn register_null_plugin() {
        let mut driver = super::new_test_driver();
        let driver = driver.as_mut().unwrap();
        let res = unsafe { driver.register_plugin_raw(std::ptr::null(), c"") };
        assert!(res.is_err())
    }
}
