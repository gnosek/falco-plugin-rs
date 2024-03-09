use crate::plugin::tables::key::ToData;
use falco_plugin_api::{ss_plugin_state_data, ss_plugin_table_field_t, ss_plugin_table_t};
use std::ffi::CStr;
use std::marker::PhantomData;

pub trait FromData<'a> {
    type Tag: 'a + ?Sized + FromDataTag<Actual<'a> = Self>;
    unsafe fn from_data(data: &'a ss_plugin_state_data) -> Self;
}

pub trait FromDataTag {
    type Actual<'a>: 'a + FromData<'a, Tag = Self> + ToData;
}

macro_rules! impl_from_data_for_numeric_type {
    ($ty:ty => $field:ident) => {
        impl FromData<'_> for $ty {
            type Tag = Self;
            unsafe fn from_data(data: &ss_plugin_state_data) -> Self {
                unsafe { data.$field }
            }
        }

        impl FromDataTag for $ty {
            type Actual<'a> = Self;
        }
    };
}

impl_from_data_for_numeric_type!(u8 => u8_);
impl_from_data_for_numeric_type!(i8 => s8);
impl_from_data_for_numeric_type!(u16 => u16_);
impl_from_data_for_numeric_type!(i16 => s16);
impl_from_data_for_numeric_type!(u32 => u32_);
impl_from_data_for_numeric_type!(i32 => s32);
impl_from_data_for_numeric_type!(u64 => u64_);
impl_from_data_for_numeric_type!(i64 => s64);

impl FromData<'_> for bool {
    type Tag = Self;
    unsafe fn from_data(data: &ss_plugin_state_data) -> Self {
        unsafe { data.b != 0 }
    }
}

impl FromDataTag for bool {
    type Actual<'a> = Self;
}

impl<'a> FromData<'a> for &'a CStr {
    type Tag = CStr;
    unsafe fn from_data(data: &ss_plugin_state_data) -> Self {
        unsafe { CStr::from_ptr(data.str_) }
    }
}

impl FromDataTag for CStr {
    type Actual<'a> = &'a CStr;
}

/// # Table field descriptor
///
/// This struct wraps an opaque pointer from the Falco plugin API, representing a particular
/// field of a table, while also remembering which data type the field holds.
///
/// You probably won't need to construct any values of this type, but you will receive
/// them from [`tables::TypedTable<K>::get_field`](`crate::tables::TypedTable::get_field`)
pub struct TypedTableField<V: FromDataTag + ?Sized> {
    pub(crate) field: *mut ss_plugin_table_field_t,
    pub(crate) table: *mut ss_plugin_table_t, // used only for validation at call site
    value_type: PhantomData<V>,
}

impl<V: FromDataTag + ?Sized> TypedTableField<V> {
    pub(crate) fn new(field: *mut ss_plugin_table_field_t, table: *mut ss_plugin_table_t) -> Self {
        Self {
            field,
            table,
            value_type: PhantomData,
        }
    }
}
