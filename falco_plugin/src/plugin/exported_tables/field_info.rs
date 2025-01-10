use crate::plugin::tables::data::FieldTypeId;
use falco_plugin_api::ss_plugin_table_fieldinfo;
use num_traits::FromPrimitive;
use std::ffi::CStr;
use std::fmt::Debug;

#[repr(transparent)]
/// `Send`able wrapper for `ss_plugin_table_fieldinfo`
///
/// This has to be public for the derive macros, but is an implementation detail of the SDK
/// and should not be used directly. The `Send` implementation only means that this type
/// can be safely dropped from another thread (since it does not have a destructor at all).
///
/// Accessing field infos is made actually safe by the per-thread storage within the Table struct
/// (otherwise the pointers would get invalidated by subsequent calls to list_fields from *any*
/// thread).
pub struct FieldInfo(ss_plugin_table_fieldinfo);

unsafe impl Send for FieldInfo {}

impl Debug for FieldInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("FieldInfo")
            .field("name", unsafe { &CStr::from_ptr(self.0.name) })
            .field("field_type", &FieldTypeId::from_u32(self.0.field_type))
            .field("read_only", &(self.0.read_only != 0))
            .finish()
    }
}

impl FieldInfo {
    pub(crate) fn new(raw: ss_plugin_table_fieldinfo) -> Self {
        FieldInfo(raw)
    }
}
