use crate::plugin::exported_tables::field_descriptor::FieldRef;
use crate::plugin::exported_tables::metadata::Metadata;
use crate::plugin::tables::data::FieldTypeId;
use falco_plugin_api::ss_plugin_table_fieldinfo;
use std::cell::RefCell;
use std::ffi::CStr;
use std::rc::Rc;

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
    fn list_fields(&self) -> Vec<ss_plugin_table_fieldinfo>;
}

impl<M: TableMetadata> TableMetadata for Rc<RefCell<M>> {
    fn get_field(&self, name: &CStr) -> Option<FieldRef> {
        self.borrow().get_field(name)
    }

    fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<FieldRef> {
        self.borrow_mut().add_field(name, field_type, read_only)
    }

    fn list_fields(&self) -> Vec<ss_plugin_table_fieldinfo> {
        self.borrow().list_fields()
    }
}
