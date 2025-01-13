use crate::plugin::exported_tables::entry::table_metadata::traits::TableMetadata;
use crate::plugin::exported_tables::field_descriptor::FieldDescriptor;
use crate::plugin::exported_tables::field_descriptor::{FieldId, FieldRef};
use crate::plugin::exported_tables::field_info::FieldInfo;
use crate::plugin::exported_tables::metadata::Metadata;
use crate::plugin::tables::data::FieldTypeId;
use falco_plugin_api::{ss_plugin_bool, ss_plugin_state_type, ss_plugin_table_fieldinfo};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::sync::Arc;

/// A struct to hold the descriptors for dynamically added fields
#[derive(Debug)]
pub struct DynamicFieldsOnly {
    pub(crate) fields: BTreeMap<CString, Arc<FieldDescriptor>>,
}

impl Metadata for DynamicFieldsOnly {
    fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            fields: Default::default(),
        })
    }
}

impl TableMetadata for DynamicFieldsOnly {
    fn get_field(&self, name: &CStr) -> Option<FieldRef> {
        let field = self.fields.get(name)?;
        Some(FieldRef::Dynamic(Arc::clone(field)))
    }

    fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<FieldRef> {
        let index = {
            if let Some(existing_field) = self.fields.get(name) {
                if existing_field.type_id == field_type && existing_field.read_only == read_only {
                    return Some(FieldRef::Dynamic(Arc::clone(existing_field)));
                }
                return None;
            }
            self.fields.len()
        };

        let name = name.to_owned();

        let field = Arc::new(FieldDescriptor {
            index: FieldId::Dynamic(index),
            type_id: field_type,
            read_only,
        });
        self.fields.insert(name.clone(), Arc::clone(&field));

        Some(FieldRef::Dynamic(field))
    }

    fn list_fields(&self) -> Vec<FieldInfo> {
        self.fields
            .iter()
            .map(|(name, field)| {
                FieldInfo::new(ss_plugin_table_fieldinfo {
                    name: name.as_ptr(),
                    field_type: field.type_id as ss_plugin_state_type,
                    read_only: field.read_only as ss_plugin_bool,
                })
            })
            .collect()
    }
}
