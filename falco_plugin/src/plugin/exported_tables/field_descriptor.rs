use crate::plugin::tables::data::FieldTypeId;

/// # A descriptor for a dynamically added field
///
/// It knows its sequential ID (to look up fields by numbers, not by strings all the time)
/// and the type of stored data.
///
/// **Note**: the data is stored as an enum capable of holding values of any type, but the table enforces
/// the defined type on all incoming data.
pub struct DynamicField {
    pub(in crate::plugin::exported_tables) index: usize,
    pub(in crate::plugin::exported_tables) type_id: FieldTypeId,
    pub(in crate::plugin::exported_tables) read_only: bool,
}
