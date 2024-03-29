use falco_plugin_api::{
    ss_plugin_log_severity, ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_DEBUG,
    ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_ERROR, ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_INFO,
    ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_TRACE,
    ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_WARNING, ss_plugin_owner_t,
};
use log::{Level, Log, Metadata, Record};
use std::ffi::{c_char, CString};

pub(super) struct FalcoPluginLogger {
    pub(super) owner: *mut ss_plugin_owner_t,
    pub(super) logger_fn: unsafe extern "C" fn(
        o: *mut ss_plugin_owner_t,
        component: *const c_char,
        msg: *const c_char,
        sev: ss_plugin_log_severity,
    ),
}
unsafe impl Send for FalcoPluginLogger {}
unsafe impl Sync for FalcoPluginLogger {}

impl Log for FalcoPluginLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let severity = match record.level() {
            Level::Error => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_ERROR,
            Level::Warn => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_WARNING,
            Level::Info => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_INFO,
            Level::Debug => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_DEBUG,
            Level::Trace => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_TRACE,
        };

        let msg = format!("{}: {}", record.target(), record.args());
        if let Ok(msg) = CString::new(msg) {
            unsafe { (self.logger_fn)(self.owner, std::ptr::null(), msg.as_ptr(), severity) }
        }
    }

    fn flush(&self) {}
}
