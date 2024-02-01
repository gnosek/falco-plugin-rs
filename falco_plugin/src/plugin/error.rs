use anyhow::Context;
use std::ffi::{c_char, CString};

use thiserror::Error;

use crate::strings::from_ptr::try_str_from_ptr;
use falco_plugin_api::{ss_plugin_owner_t, ss_plugin_rc};

#[derive(Debug, Clone, Copy, Error)]
pub enum FailureReason {
    #[error("failure")]
    Failure,

    #[error("timeout")]
    Timeout,

    #[error("end of data")]
    Eof,

    #[error("not supported")]
    NotSupported,
}

impl From<FailureReason> for ss_plugin_rc {
    fn from(value: FailureReason) -> Self {
        match value {
            FailureReason::Failure => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_FAILURE,
            FailureReason::Timeout => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_TIMEOUT,
            FailureReason::Eof => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_EOF,
            FailureReason::NotSupported => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED,
        }
    }
}

#[derive(Clone)]
pub(crate) struct LastError {
    owner: *mut ss_plugin_owner_t,
    get_owner_last_error: Option<unsafe extern "C" fn(o: *mut ss_plugin_owner_t) -> *const c_char>,
}

impl LastError {
    pub fn new(
        owner: *mut ss_plugin_owner_t,
        get_owner_last_error: Option<unsafe extern "C" fn(*mut ss_plugin_owner_t) -> *const c_char>,
    ) -> Self {
        Self {
            owner,
            get_owner_last_error,
        }
    }

    pub(crate) fn get(&self) -> Option<String> {
        let get_owner_last_error = self.get_owner_last_error?;
        let err = unsafe { get_owner_last_error(self.owner) };
        if err.is_null() {
            None
        } else {
            try_str_from_ptr(err, self).ok().map(String::from)
        }
    }
}

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

pub trait AsResult {
    fn as_result(&self) -> Result<(), FailureReason>;
    fn as_result_with_last_error(&self, last_error: &LastError) -> Result<(), anyhow::Error>;
}

impl AsResult for ss_plugin_rc {
    fn as_result(&self) -> Result<(), FailureReason> {
        use falco_plugin_api as b;
        match *self {
            b::ss_plugin_rc_SS_PLUGIN_SUCCESS => Ok(()),
            b::ss_plugin_rc_SS_PLUGIN_FAILURE => Err(FailureReason::Failure),
            b::ss_plugin_rc_SS_PLUGIN_TIMEOUT => Err(FailureReason::Timeout),
            b::ss_plugin_rc_SS_PLUGIN_EOF => Err(FailureReason::Timeout),
            b::ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED => Err(FailureReason::NotSupported),
            _ => Err(FailureReason::Failure),
        }
    }

    fn as_result_with_last_error(&self, last_error: &LastError) -> Result<(), anyhow::Error> {
        let res = self.as_result();
        if res.is_err() {
            let msg = last_error.get();
            if let Some(msg) = msg {
                return res.context(msg);
            }
        }

        Ok(res?)
    }
}
