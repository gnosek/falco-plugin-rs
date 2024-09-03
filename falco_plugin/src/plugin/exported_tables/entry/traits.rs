use crate::plugin::exported_tables::field_descriptor::FieldId;
use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
use crate::plugin::tables::data::FieldTypeId;
use falco_plugin_api::ss_plugin_state_data;
use std::ffi::CStr;

/// # A trait for structs that can be stored as table values
///
/// For tables with dynamic fields only, it's easiest to use the [`crate::tables::export::DynamicEntry`] type
/// directly, for other types, you'll probably want to use the [`crate::tables::export::Entry`] derive macro.
pub trait Entry: Default {
    /// A list of all static fields in this table
    const STATIC_FIELDS: &'static [(&'static CStr, FieldTypeId, bool)];

    /// True if this table supports adding custom fields, false otherwise
    const HAS_DYNAMIC_FIELDS: bool;

    /// Get field value by index
    ///
    /// This method must verify that `type_id` is correct for the underlying data type
    /// of the `key`th field and store the field's value in `out`.
    ///
    /// `key` will correspond to an entry in [`Entry::STATIC_FIELDS`] or to a dynamic field
    /// (if it's larger than `STATIC_FIELDS.size()`)
    fn get(
        &self,
        key: FieldId,
        type_id: FieldTypeId,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error>;

    /// Set field value by index
    ///
    /// This method must verify that `type_id` is correct for the underlying data type
    /// and store `value` under the (numeric) `key`.
    ///
    /// `key` will correspond to an entry in [`Entry::STATIC_FIELDS`] or to a dynamic field
    /// (if it's larger than `STATIC_FIELDS.size()`)
    fn set(&mut self, key: FieldId, value: DynamicFieldValue) -> Result<(), anyhow::Error>;
}
