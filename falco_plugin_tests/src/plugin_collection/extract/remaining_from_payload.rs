use crate::plugin_collection::events::countdown::Countdown;
use anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::Event;
use falco_plugin::event::fields::{FromBytes, ToBytes};
use falco_plugin::event::PluginEvent;
use falco_plugin::extract::{
    field, ExtractByteRange, ExtractFieldInfo, ExtractPlugin, ExtractRequest,
};
use falco_plugin::static_plugin;
use falco_plugin::strings::WriteIntoCString;
use falco_plugin::tables::TablesInput;
use std::ffi::{CStr, CString};

struct ExtractRemainingFromPayload;

impl Plugin for ExtractRemainingFromPayload {
    const NAME: &'static CStr = c"extract_remaining_from_payload";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }
}

impl ExtractRemainingFromPayload {
    fn extract_payload(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let event = req.event.event()?;
        let mut out = CString::default();
        out.write_into(|w| event.params.event_data.write(w))?;
        Ok(out)
    }

    fn extract_payload_with_range(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let event = req.event.event()?;
        let mut out = CString::default();
        out.write_into(|w| event.params.event_data.write(w))?;

        if *req.offset == ExtractByteRange::Requested {
            *req.offset =
                ExtractByteRange::in_plugin_data(0..event.params.event_data.binary_size());
        }

        Ok(out)
    }

    fn extract_payload_repeated(
        &mut self,
        req: ExtractRequest<Self>,
        reps: u64,
    ) -> Result<Vec<CString>, Error> {
        let event = req.event.event()?;
        let mut out = CString::default();
        out.write_into(|w| event.params.event_data.write(w))?;
        Ok(vec![out; reps as usize])
    }

    fn extract_events_remaining(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event = req.event.event()?;
        let remaining = event.params.event_data.remaining() as u64;
        Ok(remaining)
    }

    fn events_remaining_repeated(
        &mut self,
        req: ExtractRequest<Self>,
        reps: u64,
    ) -> Result<Vec<u64>, Error> {
        let event = req.event.event()?;
        let remaining: u64 = event.params.event_data.remaining() as u64;
        Ok(vec![remaining; reps as usize])
    }

    fn extract_events_remaining_with_maybe_override(
        &mut self,
        req: ExtractRequest<Self>,
        arg: Option<&CStr>,
    ) -> Result<u64, Error> {
        match arg {
            Some(s) => {
                let mut buf = s.to_bytes();
                let countdown = Countdown::from_bytes(&mut buf)?;
                Ok(countdown.remaining() as u64)
            }
            None => Ok(req.event.event()?.params.event_data.remaining() as u64),
        }
    }
}

impl ExtractPlugin for ExtractRemainingFromPayload {
    type Event<'a> = Event<PluginEvent<Countdown<'a>>>;
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("dummy.payload", &Self::extract_payload),
        field(
            "dummy.payload_with_range",
            &Self::extract_payload_with_range,
        ),
        field("dummy.payload_repeated", &Self::extract_payload_repeated),
        field("dummy.remaining", &Self::extract_events_remaining),
        field("dummy.remaining_repeated", &Self::events_remaining_repeated),
        field(
            "dummy.remaining_with_maybe_override",
            &Self::extract_events_remaining_with_maybe_override,
        ),
    ];
}

static_plugin!(pub EXTRACT_REMAINING_FROM_PAYLOAD = ExtractRemainingFromPayload);
