use std::ffi::{CStr, CString};
use std::io::Write;

use anyhow::{anyhow, Error};

use falco_plugin::base::{Json, Plugin};
use falco_plugin::schemars::JsonSchema;
use falco_plugin::serde::Deserialize;
use falco_plugin::source::{
    CStringWriter, EventBatch, EventInput, PluginEvent, SourcePlugin, SourcePluginInstance,
};
use falco_plugin::{plugin, source_plugin, EventInputExt, FailureReason};
use falco_plugin_api::ss_plugin_init_input;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Config {
    max_evts: usize,
}

pub struct DummyPlugin {
    config: Config,
}

#[derive(Debug, Default)]
pub struct DummyPluginInstance {
    num_evts: usize,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"source-plugin-rs";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"sample source plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = Json<Config>;

    fn new(
        _input: &ss_plugin_init_input,
        Json(config): Self::ConfigType,
    ) -> Result<Self, FailureReason> {
        Ok(DummyPlugin { config })
    }

    fn set_config(&mut self, Json(config): Self::ConfigType) -> Result<(), Error> {
        self.config = config;
        Ok(())
    }
}

impl SourcePlugin for DummyPlugin {
    type Instance = DummyPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"example";
    const PLUGIN_ID: u32 = 1220;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(DummyPluginInstance::default())
    }

    fn event_to_string(&mut self, event: &EventInput) -> Result<CString, Error> {
        let event_num = event.event_number();
        let event_source = event.source();
        let event = event.event()?;
        let plugin_event = event.load::<PluginEvent>()?;
        let mut writer = CStringWriter::default();
        write!(
            writer,
            "evt #{} from {:?} payload [{}]",
            event_num,
            event_source,
            plugin_event
                .params
                .event_data
                .map(|e| String::from_utf8_lossy(e))
                .unwrap_or_default()
        )?;
        Ok(writer.into_cstring())
    }
}

impl SourcePluginInstance for DummyPluginInstance {
    type Plugin = DummyPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        if plugin.config.max_evts > 0 && self.num_evts >= plugin.config.max_evts {
            return Err(anyhow!("all done").context(FailureReason::Eof));
        }
        self.num_evts += 1;

        let event = format!("hello, event {}", self.num_evts);
        let event = Self::plugin_event(event.as_bytes());
        batch.add(event)?;

        Ok(())
    }
}

plugin!(3;3;0 => DummyPlugin);
source_plugin!(DummyPlugin);
