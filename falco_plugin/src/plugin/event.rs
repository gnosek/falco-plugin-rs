use falco_event::raw_event::RawEvent;
use std::ffi::CStr;

pub use falco_plugin_api::ss_plugin_event_input;

pub trait EventInput {
    fn event(&self) -> std::io::Result<RawEvent>;

    fn source(&self) -> Option<&CStr>;

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
