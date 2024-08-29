use crate::plugin::error::last_error::LastError;
use crate::FailureReason;
use anyhow::Context;
use falco_plugin_api::ss_plugin_rc;

pub trait AsResult {
    fn as_result(&self) -> Result<(), FailureReason>;
    fn as_result_with_last_error(self, last_error: &LastError) -> Result<(), anyhow::Error>
    where
        Self: Sized,
    {
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
}
