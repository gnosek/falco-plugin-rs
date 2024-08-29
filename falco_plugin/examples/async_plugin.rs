use std::ffi::CStr;
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Error;

use falco_event::events::Event;
use falco_event::events::EventMetadata;
use falco_plugin::async_event::{AsyncEvent, AsyncEventPlugin, AsyncHandler};
use falco_plugin::base::Plugin;
use falco_plugin::{async_event_plugin, plugin, FailureReason};
use falco_plugin_api::ss_plugin_init_input;

#[derive(Default)]
struct DummyAsyncPlugin {
    stop_request: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), Error>>>,
}

impl Plugin for DummyAsyncPlugin {
    const NAME: &'static CStr = c"async-plugin-rs";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"sample async plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(
        _input: &ss_plugin_init_input,
        _config: Self::ConfigType,
    ) -> Result<Self, FailureReason> {
        Ok(DummyAsyncPlugin::default())
    }
}

impl AsyncEventPlugin for DummyAsyncPlugin {
    const ASYNC_EVENTS: &'static [&'static str] = &["sample_async"];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall", "example"];

    // TODO(example) use channels and recv_timeout instead of sleeping
    // TODO(sdk) wrapper struct for managing the thread
    fn start_async(&mut self, handler: AsyncHandler) -> Result<(), Error> {
        dbg!("start_async");
        if self.thread.is_some() {
            self.stop_async()?;
        }
        self.stop_request.store(false, Ordering::Relaxed);
        let stop_request = Arc::clone(&self.stop_request);
        self.thread = Some(std::thread::spawn(move || {
            while !stop_request.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1500));

                // TODO(sdk) some helper for generating the event
                let event = AsyncEvent {
                    plugin_id: Some(0),
                    name: Some(c"sample_async"),
                    data: Some(b"hello"),
                };

                let metadata = EventMetadata::default();

                let event = Event {
                    metadata,
                    params: event,
                };
                handler.emit(event)?;
            }
            Ok(())
        }));
        Ok(())
    }

    fn stop_async(&mut self) -> Result<(), Error> {
        dbg!("stop_async");
        self.stop_request.store(true, Ordering::Relaxed);
        let Some(handle) = self.thread.take() else {
            return Ok(());
        };

        match handle.join() {
            Ok(res) => res,
            Err(e) => panic::resume_unwind(e),
        }
    }
}

plugin!(DummyAsyncPlugin);
async_event_plugin!(DummyAsyncPlugin);
