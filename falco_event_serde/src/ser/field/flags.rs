use crate::ser::field::SerializedField;
use serde::Serialize;

falco_event_schema::derive_deftly_for_enums!(
    impl Serialize for SerializedField<&falco_event_schema::fields::types::$ttype> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let val = self.0.as_repr();
            val.serialize(serializer)
        }
    }
);

falco_event_schema::derive_deftly_for_bitflags!(
    impl Serialize for SerializedField<&falco_event_schema::fields::types::$ttype> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let val = self.0.bits();
            val.serialize(serializer)
        }
    }
);
