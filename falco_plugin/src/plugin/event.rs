use falco_event::events::RawEvent;
use std::ffi::CStr;

pub use falco_plugin_api::ss_plugin_event_input;

/// # Extension trait for event objects from the Falco plugin framework
///
/// The object contains raw pointers and is not readily available for consumption
/// in safe code. This trait provides safe accessors for the fields inside
pub trait EventInput {
    /// # Get the event
    ///
    /// This method parses the raw event data into a [`RawEvent`] instance,
    /// which can be later converted into a specific event type.
    fn event(&self) -> std::io::Result<RawEvent>;

    /// # Get the event source
    ///
    /// Return the event source (if any)
    fn source(&self) -> Option<&CStr>;

    /// # Get the event number
    ///
    /// Return the event number as determined by the plugin framework
    fn event_number(&self) -> usize;
}

impl EventInput for ss_plugin_event_input {
    fn event(&self) -> std::io::Result<RawEvent> {
        unsafe { RawEvent::from_ptr(self.evt as *const _) }
    }

    fn source(&self) -> Option<&CStr> {
        unsafe {
            if self.evtsrc.is_null() {
                None
            } else {
                Some(CStr::from_ptr(self.evtsrc))
            }
        }
    }

    fn event_number(&self) -> usize {
        self.evtnum as usize
    }
}
