use crate::plugin::tables::data::Value;
use falco_plugin_api::ss_plugin_table_field_t;
use std::marker::PhantomData;

pub struct RawField<V: Value + ?Sized> {
    pub(in crate::plugin::tables) field: *mut ss_plugin_table_field_t,
    pub(in crate::plugin::tables) value_type: PhantomData<V>,
}
