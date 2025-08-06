use crate::ser::field::SerializedField;
use falco_event_schema::fields::types;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

impl Serialize for SerializedField<&types::PT_FDLIST<'_>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let it = self.0.iter();
        let mut state = serializer.serialize_seq(Some(it.len()))?;
        for (fd, flags) in it {
            state.serialize_element(&(fd, SerializedField(&flags)))?;
        }
        state.end()
    }
}
