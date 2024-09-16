use crate::plugin::exported_tables::entry::traits::TableValues;
use crate::plugin::tables::data::FieldTypeId;
use crate::tables::export::{DynamicFieldValue, FieldValue};
use falco_plugin_api::ss_plugin_state_data;
use std::collections::BTreeMap;
use std::ffi::CStr;

/// A table value type that only has dynamic fields
pub type DynamicFieldValues = BTreeMap<usize, DynamicFieldValue>;

impl TableValues for DynamicFieldValues {
    const STATIC_FIELDS: &'static [(&'static CStr, FieldTypeId, bool)] = &[];
    const HAS_DYNAMIC_FIELDS: bool = true;

    fn get(
        &self,
        key: usize,
        type_id: FieldTypeId,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        if let Some((_, actual_type_id, _)) = Self::STATIC_FIELDS.get(key) {
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
            .ok_or_else(|| anyhow::anyhow!("Dynamic field {} not found", key))?;

        field.to_data(out, type_id)
    }

    fn set(&mut self, key: usize, value: DynamicFieldValue) -> Result<(), anyhow::Error> {
        self.insert(key, value);
        Ok(())
    }
}
