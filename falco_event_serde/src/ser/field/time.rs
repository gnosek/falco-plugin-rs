use crate::ser::field::SerializedField;
use falco_event_schema::fields::types;
use serde::{Serialize, Serializer};

impl Serialize for SerializedField<&types::PT_ABSTIME> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.0.serialize(serializer)
    }
}

impl Serialize for SerializedField<&types::PT_RELTIME> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let nanos = self.0.as_nanos() as u64;
        nanos.serialize(serializer)
    }
}
