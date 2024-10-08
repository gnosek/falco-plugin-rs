use super::ScapStatus;
use crate::common::{Api, CaptureNotStarted, CaptureStarted};
use cxx;
use cxx::UniquePtr;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

#[allow(clippy::missing_safety_doc)]
#[cxx::bridge]
mod ffi {
    struct SinspEvent {
        rc: i32,
        evt: *mut c_char,
    }

    struct SinspMetric {
        name: UniquePtr<CxxString>,
        value: u64,
    }

    extern "Rust" {
        type Api;
    }

    unsafe extern "C++" {
        include!("falco_plugin_tests/c++/sinsp_test_driver.h");

        type SinspTestDriver;
        type sinsp_plugin;

        fn new_test_driver() -> UniquePtr<SinspTestDriver>;

        unsafe fn register_plugin(
            self: Pin<&mut SinspTestDriver>,
            plugin: *const Api,
            config: *const c_char,
        ) -> Result<SharedPtr<sinsp_plugin>>;

        unsafe fn add_filterchecks(
            self: Pin<&mut SinspTestDriver>,
            plugin: &SharedPtr<sinsp_plugin>,
            source: *const c_char,
        ) -> Result<()>;

        unsafe fn load_capture_file(
            self: Pin<&mut SinspTestDriver>,
            path: *const c_char,
        ) -> Result<()>;

        unsafe fn start_capture(
            self: Pin<&mut SinspTestDriver>,
            name: *const c_char,
            config: *const c_char,
        ) -> Result<()>;

        fn next(self: Pin<&mut SinspTestDriver>) -> SinspEvent;

        unsafe fn event_field_as_string(
            self: Pin<&mut SinspTestDriver>,
            field_name: *const c_char,
            event: &SinspEvent,
        ) -> Result<UniquePtr<CxxString>>;

        fn get_metrics(
            self: Pin<&mut SinspTestDriver>,
        ) -> Result<UniquePtr<CxxVector<SinspMetric>>>;
    }
}

pub struct SinspEvent {
    event: ffi::SinspEvent,
}

pub struct SinspMetric {
    pub name: String,
    pub value: u64,
}

pub struct SinspPlugin {
    plugin: cxx::SharedPtr<ffi::sinsp_plugin>,
}

impl Debug for SinspPlugin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SinspPlugin")
    }
}

pub struct SinspTestDriver<S> {
    driver: UniquePtr<ffi::SinspTestDriver>,
    state: PhantomData<S>,
}

impl<S> Debug for SinspTestDriver<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SinspTestDriver")
    }
}

impl SinspTestDriver<CaptureNotStarted> {
    pub fn register_plugin(&mut self, api: &Api, config: &CStr) -> anyhow::Result<SinspPlugin> {
        let plugin = unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .register_plugin(api as *const _, config.as_ptr())?
        };
        Ok(SinspPlugin { plugin })
    }

    /// # Safety
    ///
    /// `plugin` must be a pointer accepted by the sinsp API
    pub unsafe fn register_plugin_raw(
        &mut self,
        api: *const Api,
        config: &CStr,
    ) -> anyhow::Result<SinspPlugin> {
        let plugin = unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .register_plugin(api, config.as_ptr())?
        };
        Ok(SinspPlugin { plugin })
    }

    pub fn add_filterchecks(&mut self, plugin: &SinspPlugin, source: &CStr) -> anyhow::Result<()> {
        unsafe {
            Ok(self
                .driver
                .as_mut()
                .unwrap()
                .add_filterchecks(&plugin.plugin, source.as_ptr())?)
        }
    }

    pub fn load_capture_file(
        mut self,
        path: &CStr,
    ) -> anyhow::Result<SinspTestDriver<CaptureStarted>> {
        unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .load_capture_file(path.as_ptr())?;
        }

        Ok(SinspTestDriver::<CaptureStarted> {
            driver: self.driver,
            state: PhantomData,
        })
    }

    pub fn start_capture(
        mut self,
        name: &CStr,
        config: &CStr,
    ) -> anyhow::Result<SinspTestDriver<CaptureStarted>> {
        unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .start_capture(name.as_ptr(), config.as_ptr())?;
        }

        Ok(SinspTestDriver::<CaptureStarted> {
            driver: self.driver,
            state: PhantomData,
        })
    }
}

impl SinspTestDriver<CaptureStarted> {
    pub fn next_event(&mut self) -> Result<SinspEvent, ScapStatus> {
        let event = self.driver.as_mut().unwrap().next();
        match event.rc {
            0 => Ok(SinspEvent { event }),
            1 => Err(ScapStatus::Failure),
            -1 => Err(ScapStatus::Timeout),
            6 => Err(ScapStatus::Eof),
            9 => Err(ScapStatus::NotSupported),
            e => Err(ScapStatus::Other(e)),
        }
    }

    pub fn event_field_as_string(
        &mut self,
        field_name: &CStr,
        event: &SinspEvent,
    ) -> anyhow::Result<Option<String>> {
        let event_str = unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .event_field_as_string(field_name.as_ptr(), &event.event)?
        };

        if event_str.is_null() {
            Ok(None)
        } else {
            Ok(Some(event_str.to_string_lossy().to_string()))
        }
    }

    pub fn get_metrics(&mut self) -> anyhow::Result<Vec<SinspMetric>> {
        let mut out = Vec::new();
        let metrics = self.driver.as_mut().unwrap().get_metrics()?;

        anyhow::ensure!(!metrics.is_null(), "null metrics");
        for metric in metrics.as_ref().unwrap() {
            anyhow::ensure!(!metric.name.is_null(), "null metric name");
            let name = metric.name.as_ref().unwrap().to_string_lossy().to_string();
            let value = metric.value;

            out.push(SinspMetric { name, value });
        }

        Ok(out)
    }
}

pub fn new_test_driver() -> anyhow::Result<SinspTestDriver<CaptureNotStarted>> {
    let driver = ffi::new_test_driver();
    anyhow::ensure!(!driver.is_null(), "null driver");
    Ok(SinspTestDriver {
        driver,
        state: PhantomData,
    })
}
