use crate::plugin::exported_tables::field_descriptor::FieldRef;
use crate::plugin::exported_tables::field_info::FieldInfo;
use crate::plugin::exported_tables::metadata::Metadata;
use crate::plugin::exported_tables::ref_shared::RefShared;
use crate::plugin::tables::data::FieldTypeId;
use std::ffi::CStr;

/// Trait implemented by metadata types belonging to tables
///
/// This is only expected to be used by the derive macro
pub trait TableMetadata: Metadata {
    /// Get a field descriptor for an existing field
    fn get_field(&self, name: &CStr) -> Option<FieldRef>;

    /// Add a new field and return its descriptor
    fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<FieldRef>;

    /// List all fields
    fn list_fields(&self) -> Vec<FieldInfo>;
}

impl<M: TableMetadata> TableMetadata for RefShared<M> {
    fn get_field(&self, name: &CStr) -> Option<FieldRef> {
        self.read_arc().get_field(name)
    }

    fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<FieldRef> {
        self.write_arc().add_field(name, field_type, read_only)
    }

    fn list_fields(&self) -> Vec<FieldInfo> {
        self.read_arc().list_fields()
    }
}
