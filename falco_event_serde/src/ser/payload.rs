use crate::ser::field::SerializedField;
use derive_deftly::derive_deftly_adhoc;
use serde::Serialize;
use serde::ser::SerializeStruct;

pub struct SerializedPayload<T>(T);

falco_event_schema::derive_deftly_for_events! {
    impl<$tgens> Serialize for SerializedPayload<&falco_event_schema::events::$ttype> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            #[allow(clippy::identity_op)]
            let nfields = 0 ${for fields {+ 1}};

            #[allow(unused_mut)]
            let mut state = serializer.serialize_struct(
                stringify!($tname),
                nfields,
            )?;

            $(state.serialize_field(
                stringify!($fname),
                &SerializedField(&self.0.$fname),
            )?;)

            state.end()
        }
    }
}

derive_deftly_adhoc! {
    falco_event_schema::AnyEvent:

    #[derive(Serialize)]
    pub enum AnyEvent<$tgens 'ser> {
        $(${vdefbody $vname $(${fdefine $fname} SerializedPayload<&'ser falco_event_schema::events::$ftype>)})
    }

    impl<'a, 'ser> From<&'ser falco_event_schema::events::AnyEvent<'a>> for AnyEvent<'a, 'ser> {
        fn from(event: &'ser falco_event_schema::events::AnyEvent<'a>) -> Self {
            match event {
                $(falco_event_schema::events::AnyEvent::$vname(f_0) => AnyEvent::$vname(SerializedPayload(f_0)),)
            }
        }
    }

    ${for fields {
        impl<'a, 'ser> From<&'ser falco_event_schema::events::$ftype> for AnyEvent<'a, 'ser> {
            fn from(event: &'ser falco_event_schema::events::$ftype) -> Self {
                AnyEvent::$vname(SerializedPayload(event))
            }
        }
    }}
}
