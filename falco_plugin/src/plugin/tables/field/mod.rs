use crate::plugin::tables::data::Value;
use crate::plugin::tables::field::raw::RawField;
use falco_plugin_api::ss_plugin_table_t;

pub(in crate::plugin::tables) mod raw;

/// # Table field descriptor
///
/// This struct wraps an opaque pointer from the Falco plugin API, representing a particular
/// field of a table, while also remembering which data type the field holds.
///
/// You probably won't need to construct any values of this type, but you will receive
/// them from [`tables::TypedTable<K>::get_field`](`crate::tables::TypedTable::get_field`)
pub struct Field<V: Value + ?Sized> {
    pub(in crate::plugin::tables) field: RawField<V>,
    pub(in crate::plugin::tables) table: *mut ss_plugin_table_t, // used only for validation at call site
}

impl<V: Value + ?Sized> Field<V> {
    pub(crate) fn new(field: RawField<V>, table: *mut ss_plugin_table_t) -> Self {
        Self { field, table }
    }
}
