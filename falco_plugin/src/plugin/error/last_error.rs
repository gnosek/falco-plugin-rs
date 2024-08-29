use crate::strings::from_ptr::try_str_from_ptr;
use falco_plugin_api::ss_plugin_owner_t;
use std::ffi::c_char;

#[derive(Clone, Debug)]
pub struct LastError {
    owner: *mut ss_plugin_owner_t,
    get_owner_last_error: unsafe extern "C" fn(o: *mut ss_plugin_owner_t) -> *const c_char,
}

impl LastError {
    pub unsafe fn new(
        owner: *mut ss_plugin_owner_t,
        get_owner_last_error: unsafe extern "C" fn(*mut ss_plugin_owner_t) -> *const c_char,
    ) -> Self {
        Self {
            owner,
            get_owner_last_error,
        }
    }

    pub(crate) fn get(&self) -> Option<String> {
        let err = unsafe { (self.get_owner_last_error)(self.owner) };
        if err.is_null() {
            None
        } else {
            let msg = match try_str_from_ptr(err, self) {
                Ok(msg) => String::from(msg),
                Err(e) => e.to_string(),
            };

            log::warn!("Got error from API: {}", msg);
            Some(msg)
        }
    }
}
