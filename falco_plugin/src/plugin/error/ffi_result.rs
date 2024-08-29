use crate::FailureReason;
use falco_plugin_api::ss_plugin_rc;
use std::ffi::CString;

#[doc(hidden)]
pub trait FfiResult {
    fn status_code(&self) -> ss_plugin_rc;
    fn set_last_error(&self, lasterr: &mut CString);
}

impl FfiResult for anyhow::Error {
    fn status_code(&self) -> ss_plugin_rc {
        match self.downcast_ref::<FailureReason>() {
            Some(reason) => ss_plugin_rc::from(*reason),
            None => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_FAILURE,
        }
    }

    fn set_last_error(&self, lasterr: &mut CString) {
        let msg = self.to_string();
        if let Ok(mut msg) = CString::new(msg.into_bytes()) {
            std::mem::swap(lasterr, &mut msg);
        }
    }
}

impl<T> FfiResult for Result<T, anyhow::Error> {
    fn status_code(&self) -> ss_plugin_rc {
        match self {
            Ok(_) => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS,
            Err(e) => e.status_code(),
        }
    }

    fn set_last_error(&self, lasterr: &mut CString) {
        if let Err(e) = self {
            e.set_last_error(lasterr)
        }
    }
}

impl<T> FfiResult for Result<T, FailureReason> {
    fn status_code(&self) -> ss_plugin_rc {
        match self {
            Ok(_) => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS,
            Err(e) => (*e).into(),
        }
    }

    fn set_last_error(&self, _lasterr: &mut CString) {}
}
