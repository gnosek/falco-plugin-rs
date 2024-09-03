use crate::plugin::exported_tables::entry::traits::Entry;
use crate::plugin::exported_tables::field_descriptor::FieldId;
use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
use crate::plugin::exported_tables::field_value::traits::FieldValue;
use crate::plugin::tables::data::FieldTypeId;
use falco_plugin_api::ss_plugin_state_data;
use std::collections::BTreeMap;
use std::ffi::CStr;

/// A table value type that only has dynamic fields
pub type DynamicEntry = BTreeMap<FieldId, DynamicFieldValue>;

impl Entry for DynamicEntry {
    const STATIC_FIELDS: &'static [(&'static CStr, FieldTypeId, bool)] = &[];
    const HAS_DYNAMIC_FIELDS: bool = true;

    fn get(
        &self,
        key: FieldId,
        type_id: FieldTypeId,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        let FieldId::Dynamic(static_field_id) = key;
        if let Some((_, actual_type_id, _)) = Self::STATIC_FIELDS.get(static_field_id) {
            if type_id != *actual_type_id {
                return Err(anyhow::anyhow!(
                    "Type mismatch, requested {:?}, actual type is {:?}",
                    type_id,
                    actual_type_id
                ));
            };
        }

        let field = self
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("Dynamic field {:?} not found", key))?;

        field.to_data(out, type_id)
    }

    fn set(&mut self, key: FieldId, value: DynamicFieldValue) -> Result<(), anyhow::Error> {
        self.insert(key, value);
        Ok(())
    }
}
