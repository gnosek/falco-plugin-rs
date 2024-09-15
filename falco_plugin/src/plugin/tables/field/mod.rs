use crate::plugin::tables::data::Value;
use crate::plugin::tables::field::raw::RawField;
use crate::plugin::tables::runtime::RuntimeEntry;
use crate::plugin::tables::runtime_table_validator::RuntimeTableValidator;
use std::marker::PhantomData;

pub(in crate::plugin::tables) mod raw;

/// # Table field descriptor
///
/// This struct wraps an opaque pointer from the Falco plugin API, representing a particular
/// field of a table, while also remembering which data type the field holds.
///
/// You probably won't need to construct any values of this type, but you will receive
/// them from [`tables::TypedTable<K>::get_field`](`crate::tables::Table::get_field`)
pub struct Field<V: Value + ?Sized, T = RuntimeEntry<()>> {
    pub(in crate::plugin::tables) field: RawField<V>,
    pub(in crate::plugin::tables) validator: RuntimeTableValidator,
    pub(in crate::plugin::tables) tag: PhantomData<T>,
}

impl<V: Value + ?Sized, T> Field<V, T> {
    pub(crate) fn new(field: RawField<V>, validator: RuntimeTableValidator) -> Self {
        Self {
            field,
            validator,
            tag: PhantomData,
        }
    }
}
