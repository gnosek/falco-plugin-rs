use crate::plugin::tables::data::FieldTypeId;
use std::rc::Rc;

/// A reference to a field descriptor
///
/// For static fields, it's a static reference to the descriptor (stored in a static global
/// somewhere). For dynamic fields, it's a reference-counted pointer to the descriptor living
/// in a runtime-managed map
#[allow(missing_docs)]
pub enum FieldRef {
    Dynamic(Rc<FieldDescriptor>),
}

impl AsRef<FieldDescriptor> for FieldRef {
    fn as_ref(&self) -> &FieldDescriptor {
        match self {
            FieldRef::Dynamic(d) => d.as_ref(),
        }
    }
}

/// # A descriptor for a dynamically added field
///
/// It knows its sequential ID (to look up fields by numbers, not by strings all the time)
/// and the type of stored data.
///
/// **Note**: the data is stored as an enum capable of holding values of any type, but the table enforces
/// the defined type on all incoming data.
pub struct FieldDescriptor {
    pub(in crate::plugin::exported_tables) index: usize,
    pub(in crate::plugin::exported_tables) type_id: FieldTypeId,
    pub(in crate::plugin::exported_tables) read_only: bool,
}
