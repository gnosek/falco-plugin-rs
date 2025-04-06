use anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::RawEvent;
use falco_plugin::source::{EventBatch, EventInput, SourcePlugin, SourcePluginInstance};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use std::ffi::{CStr, CString};

#[derive(Debug)]
pub struct BatchedEmptyEvent(usize);

impl Plugin for BatchedEmptyEvent {
    const NAME: &'static CStr = c"batched_empty_event";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = String;

    fn new(_input: Option<&TablesInput>, config: Self::ConfigType) -> Result<Self, Error> {
        let batch_size = config.parse::<usize>().ok().unwrap();
        Ok(Self(batch_size))
    }
}

pub struct BatchedEmptyEventInstance;

impl SourcePluginInstance for BatchedEmptyEventInstance {
    type Plugin = BatchedEmptyEvent;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        let batch_size = plugin.0;
        for _ in 0..batch_size {
            let event = Self::plugin_event(&[]);
            batch.add(event)?;
        }
        Ok(())
    }
}

impl SourcePlugin for BatchedEmptyEvent {
    type Instance = BatchedEmptyEventInstance;
    const EVENT_SOURCE: &'static CStr = c"batched_empty_event";
    const PLUGIN_ID: u32 = 1111;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(BatchedEmptyEventInstance)
    }

    fn event_to_string(&mut self, _event: &EventInput<RawEvent>) -> Result<CString, Error> {
        Ok(CString::from(c"<NA>"))
    }
}

static_plugin!(pub BATCHED_EMPTY_EVENT = BatchedEmptyEvent);
