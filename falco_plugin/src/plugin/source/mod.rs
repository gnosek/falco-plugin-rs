use std::ffi::{CStr, CString};

use falco_event::events::PPME_PLUGINEVENT_E as PluginEvent;
use falco_event::{Event, EventMetadata};

use crate::plugin::base::Plugin;
use crate::plugin::source::event_batch::EventBatchStorage;
use crate::source::{EventBatch, EventInput};

pub mod event_batch;
pub mod open_params;
#[doc(hidden)]
pub mod wrappers;

/// # Support for event sourcing plugins
pub trait SourcePlugin: Plugin {
    /// # Instance type
    ///
    /// Each source plugin defines an instance type. The instance is the object responsible
    /// for actual generation of events. The plugin type mostly serves as a way to create
    /// and destroy instances.
    ///
    /// **Note**: while there may be multiple instances for a particular plugin, there will be
    /// at most one at any given time.
    type Instance: SourcePluginInstance<Plugin = Self>;

    /// # Event source name
    ///
    /// This string describes the event source. One notable event source name is `syscall`,
    /// for plugins collecting syscall information.
    ///
    /// If the plugin defines both `EVENT_SOURCE` and `PLUGIN_ID`, it will only be allowed to emit
    /// events of type [`PluginEvent`] with the `plugin_id` field matching
    /// `PLUGIN_ID` in the definition of this trait.
    ///
    /// This constant must be a non-empty string if `PLUGIN_ID` is set.
    const EVENT_SOURCE: &'static CStr;

    /// # Plugin ID
    ///
    /// This is the unique ID of the plugin.
    ///
    /// If the plugin defines both `EVENT_SOURCE` and `PLUGIN_ID`, it will only be allowed to emit
    /// events of type [`PluginEvent`] with the `plugin_id` field matching
    /// `PLUGIN_ID` in the definition of this trait.
    ///
    /// EVERY PLUGIN WITH EVENT SOURCING CAPABILITY IMPLEMENTING A SPECIFIC EVENT SOURCE MUST OBTAIN
    /// AN OFFICIAL ID FROM THE FALCOSECURITY ORGANIZATION, OTHERWISE IT WON'T PROPERLY COEXIST
    /// WITH OTHER PLUGINS.
    const PLUGIN_ID: u32;

    /// # List sample open parameters
    ///
    /// Return a list of suggested open parameters supported by this plugin.
    /// Any of the values in the returned list are valid parameters for open().
    ///
    /// The default implementation returns an empty string, but you can use
    /// [`crate::source::serialize_open_params`] and [`crate::source::OpenParam`] to build
    /// a description of what the [`SourcePlugin::open`] method expects.
    ///
    /// **Note**: as of API version 3.4.0, this appears unused.
    fn list_open_params(&mut self) -> Result<&CStr, anyhow::Error> {
        Ok(unsafe { CStr::from_ptr(b"\0".as_ptr().cast()) })
    }

    /// # Open a capture instance
    ///
    /// This method receives the `open` parameter from Falco configuration and returns
    /// a new instance of the source plugin.
    fn open(&mut self, params: Option<&str>) -> Result<Self::Instance, anyhow::Error>;

    /// # Close a capture instance
    ///
    /// The default implementation does nothing, leaving all cleanup to the instance type's
    /// [`Drop`] implementation, if any.
    fn close(&mut self, _instance: &mut Self::Instance) {}

    /// # Render an event to string
    ///
    /// This string will be available as `%evt.plugininfo` in Falco rules.
    fn event_to_string(
        &mut self,
        event: &EventInput,
        output: &mut CString,
    ) -> Result<(), anyhow::Error>;
}

pub struct ProgressInfo<'a> {
    value: f64,
    detail: Option<&'a CStr>,
}

pub(crate) struct SourcePluginInstanceWrapper<I: SourcePluginInstance> {
    pub(crate) instance: I,
    pub(crate) batch: EventBatchStorage,
}

pub trait SourcePluginInstance {
    type Plugin: SourcePlugin<Instance = Self>;

    // TODO document that this should not sleep forever (but also should not spin)
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
