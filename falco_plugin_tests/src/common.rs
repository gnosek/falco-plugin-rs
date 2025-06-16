use anyhow::Context;
use cxx::{type_id, ExternType};
use falco_plugin_runner::ExtractedField;
pub use falco_plugin_runner::ScapStatus;
use std::ffi::CStr;
use std::fmt::Debug;
use std::ops::Range;

pub struct CaptureNotStarted;

pub struct CaptureStarted;

#[repr(transparent)]
pub struct Api(pub falco_plugin::api::plugin_api);

unsafe impl ExternType for Api {
    type Id = type_id!("falco_plugin_api");
    type Kind = cxx::kind::Opaque;
}

#[repr(C)]
pub struct RawExtractedValue {
    pub ptr: *const u8,
    pub len: u32,
}

unsafe impl ExternType for RawExtractedValue {
    type Id = type_id!("extract_value_t");
    type Kind = cxx::kind::Trivial;
}

pub struct SinspMetric {
    pub name: String,
    pub value: u64, // TODO: this is... taking shortcuts
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformData {
    Enabled,
    Disabled,
}

pub trait TestDriver: Debug + Sized {
    type Capturing: CapturingTestDriver<NonCapturing = Self>;
    type Plugin: Debug;

    fn new() -> anyhow::Result<Self>;

    fn register_plugin(
        &mut self,
        api: &'static falco_plugin::api::plugin_api,
        config: &CStr,
    ) -> anyhow::Result<Self::Plugin>;

    /// # Safety
    /// `api` must be a valid pointer (or null, to be caught by the framework)
    unsafe fn register_plugin_raw(
        &mut self,
        api: *const falco_plugin::api::plugin_api,
        config: &CStr,
    ) -> anyhow::Result<Self::Plugin>;

    fn add_filterchecks(&mut self, plugin: &Self::Plugin, source: &CStr) -> anyhow::Result<()>;

    fn start_capture(
        self,
        name: &CStr,
        config: &CStr,
        platform_data: PlatformData,
    ) -> anyhow::Result<Self::Capturing>;
}

pub trait SavefileTestDriver: TestDriver {
    fn load_capture_file(self, path: &CStr) -> anyhow::Result<Self::Capturing>;
}

pub trait AsPtr {
    fn as_ptr(&self) -> *const u8;
}

pub trait CapturingTestDriver {
    type NonCapturing: TestDriver<Capturing = Self>;
    type Event: AsPtr;

    fn next_event(&mut self) -> Result<Self::Event, ScapStatus>;

    fn event_field_as_string(
        &mut self,
        field_name: &CStr,
        event: &Self::Event,
    ) -> anyhow::Result<Option<String>>;

    fn event_field_as_string_with_range(
        &mut self,
        field_name: &CStr,
        event: &Self::Event,
    ) -> anyhow::Result<Option<(String, Range<usize>)>>;

    fn event_field_is_none(&mut self, field_name: &CStr, event: &Self::Event) -> bool;

    fn extract_field(
        &mut self,
        field_name: &CStr,
        event: &Self::Event,
    ) -> anyhow::Result<Option<ExtractedField>>;

    fn get_metrics(&mut self) -> anyhow::Result<Vec<SinspMetric>>;

    fn next_event_as_str(&mut self) -> anyhow::Result<Option<String>> {
        let event = match self.next_event() {
            Ok(event) => event,
            Err(e) => return Err(anyhow::anyhow!("{:?}", e)).context(e),
        };
        self.event_field_as_string(c"evt.plugininfo", &event)
    }
}
