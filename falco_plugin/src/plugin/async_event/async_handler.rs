use crate::plugin::error::AsResult;
use crate::strings::from_ptr::try_str_from_ptr;
use anyhow::Context;
use falco_event::events::PPME_ASYNCEVENT_E as AsyncEvent;
use falco_event::{Event, EventToBytes};
use falco_plugin_api::{ss_plugin_event, ss_plugin_owner_t, ss_plugin_rc, PLUGIN_MAX_ERRLEN};
use std::ffi::c_char;

pub struct AsyncHandler {
    pub(crate) owner: *mut ss_plugin_owner_t,
    pub(crate) raw_handler: unsafe extern "C" fn(
        o: *mut ss_plugin_owner_t,
        evt: *const ss_plugin_event,
        err: *mut c_char,
    ) -> ss_plugin_rc,
}

unsafe impl Send for AsyncHandler {}
unsafe impl Sync for AsyncHandler {}

impl AsyncHandler {
    pub fn emit(&self, event: Event<AsyncEvent>) -> Result<(), anyhow::Error> {
        let mut err = [0i8; PLUGIN_MAX_ERRLEN as usize];
        let mut buf = Vec::new();

        event.write(&mut buf)?;
        match unsafe {
            (self.raw_handler)(self.owner, buf.as_ptr() as *const _, err.as_mut_ptr()).as_result()
        } {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = try_str_from_ptr(err.as_ptr(), &err)?;
                Err(e).context(msg.to_string())
            }
        }
    }
}
