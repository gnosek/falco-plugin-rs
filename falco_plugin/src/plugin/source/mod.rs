use std::ffi::{CStr, CString};

use falco_event::events::PPME_PLUGINEVENT_E as PluginEvent;
use falco_event::{Event, EventMetadata};
use falco_plugin_api::ss_plugin_event_input;

use crate::plugin::base::Plugin;
use crate::plugin::source::event_batch::EventBatchStorage;
use crate::source::EventBatch;
use crate::FailureReason;

pub mod event_batch;
pub mod open_params;
pub mod wrappers;

pub trait SourcePlugin: Plugin {
    type Instance: SourcePluginInstance<Plugin = Self>;
    const EVENT_SOURCE: &'static CStr;
    const PLUGIN_ID: u32;

    fn list_open_params(&mut self) -> Result<&CStr, anyhow::Error> {
        Ok(unsafe { CStr::from_ptr(b"\0".as_ptr().cast()) })
    }

    fn open(&mut self, params: Option<&str>) -> Result<Self::Instance, anyhow::Error>;
    fn close(&mut self, _instance: &mut Self::Instance) {}

    fn event_to_string(
        &mut self,
        _event: &ss_plugin_event_input,
        _output: &mut CString,
    ) -> Result<(), anyhow::Error> {
        Err(FailureReason::NotSupported.into())
    }
}

pub struct ProgressInfo<'a> {
    value: f64,
    detail: Option<&'a CStr>,
}

pub struct SourcePluginInstanceWrapper<I: SourcePluginInstance> {
    pub(crate) instance: I,
    pub(crate) batch: EventBatchStorage,
}

pub trait SourcePluginInstance {
    type Plugin: SourcePlugin<Instance = Self>;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), anyhow::Error>;

    fn get_progress(&mut self) -> ProgressInfo {
        ProgressInfo {
            value: 0.0,
            detail: None,
        }
    }

    fn plugin_event(data: &[u8]) -> Event<PluginEvent> {
        let event = PluginEvent {
            plugin_id: Some(Self::Plugin::PLUGIN_ID),
            event_data: Some(data),
        };

        let metadata = EventMetadata::default();

        Event {
            metadata,
            params: event,
        }
    }
}
