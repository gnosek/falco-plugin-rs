use std::ffi::CStr;

use falco_event::type_id::TypeId;
use falco_plugin_api::ss_plugin_state_data;

use crate::plugin::tables::field::FromData;

pub trait ToData {
    const TYPE_ID: TypeId;

    fn to_data(&self) -> ss_plugin_state_data;
}
macro_rules! impl_to_data_for_numeric_type {
    ($ty:ty => $field:ident : $type_id:expr) => {
        impl ToData for $ty {
            const TYPE_ID: TypeId = $type_id;

            fn to_data(&self) -> ss_plugin_state_data {
                ss_plugin_state_data { $field: *self }
            }
        }
    };
}

impl_to_data_for_numeric_type!(u8 => u8_ : TypeId::U8);
impl_to_data_for_numeric_type!(i8 => s8 : TypeId::I8);
impl_to_data_for_numeric_type!(u16 => u16_: TypeId::U16);
impl_to_data_for_numeric_type!(i16 => s16: TypeId::I16);
impl_to_data_for_numeric_type!(u32 => u32_: TypeId::U32);
impl_to_data_for_numeric_type!(i32 => s32: TypeId::I32);
impl_to_data_for_numeric_type!(u64 => u64_: TypeId::U64);
impl_to_data_for_numeric_type!(i64 => s64: TypeId::I64);

impl ToData for bool {
    const TYPE_ID: TypeId = TypeId::Bool;

    fn to_data(&self) -> ss_plugin_state_data {
        ss_plugin_state_data {
            b: if *self { 1 } else { 0 },
        }
    }
}

impl<'a> ToData for &'a CStr {
    const TYPE_ID: TypeId = TypeId::CharBuf;

    fn to_data(&self) -> ss_plugin_state_data {
        ss_plugin_state_data {
            str_: self.as_ptr(),
        }
    }
}

pub trait TableKey: ToData + for<'a> FromData<'a> {}

impl<T: ToData + for<'a> FromData<'a>> TableKey for T {}
