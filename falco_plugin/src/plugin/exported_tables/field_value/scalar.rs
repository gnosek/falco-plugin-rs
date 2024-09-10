use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
use crate::plugin::exported_tables::field_value::traits::{seal, FieldValue, StaticField};
use crate::plugin::tables::data::FieldTypeId;
use falco_plugin_api::ss_plugin_state_data;
use std::ffi::{CStr, CString};

macro_rules! impl_field_value {
    ($ty:ty => $datafield:ident => $type_id:expr => $variant:ident) => {
        impl seal::Sealed for $ty {}

        impl FieldValue for $ty {
            fn to_data(
                &self,
                out: &mut ss_plugin_state_data,
                type_id: FieldTypeId,
            ) -> Result<(), anyhow::Error> {
                if type_id != $type_id {
                    anyhow::bail!(
                        "Type mismatch, requested {:?}, got {:?}",
                        type_id,
                        stringify!($ty)
                    )
                }

                out.$datafield = *self;
                Ok(())
            }

            unsafe fn from_data(
                value: &ss_plugin_state_data,
                type_id: FieldTypeId,
            ) -> Option<Self> {
                if type_id != $type_id {
                    return None;
                }

                Some(value.$datafield)
            }
        }

        impl StaticField for $ty {
            const TYPE_ID: FieldTypeId = $type_id;
        }

        impl TryFrom<DynamicFieldValue> for $ty {
            type Error = anyhow::Error;

            fn try_from(value: DynamicFieldValue) -> Result<Self, Self::Error> {
                if let DynamicFieldValue::$variant(val) = value {
                    Ok(val)
                } else {
                    Err(anyhow::anyhow!(
                        "Type mismatch, expected {}, got {:?}",
                        stringify!($ty),
                        value
                    ))
                }
            }
        }
    };
}

impl_field_value!(u8 => u8_ => FieldTypeId::U8 => U8);
impl_field_value!(i8 => s8 => FieldTypeId::I8 => I8);
impl_field_value!(u16 => u16_ => FieldTypeId::U16 => U16);
impl_field_value!(i16 => s16 => FieldTypeId::I16 => I16);
impl_field_value!(u32 => u32_ => FieldTypeId::U32 => U32);
impl_field_value!(i32 => s32 => FieldTypeId::I32 => I32);
impl_field_value!(u64 => u64_ => FieldTypeId::U64 => U64);
impl_field_value!(i64 => s64 => FieldTypeId::I64 => I64);

impl seal::Sealed for bool {}

impl FieldValue for bool {
    fn to_data(
        &self,
        out: &mut ss_plugin_state_data,
        type_id: FieldTypeId,
    ) -> Result<(), anyhow::Error> {
        if type_id != FieldTypeId::Bool {
            anyhow::bail!("Type mismatch, requested {:?}, got bool", type_id)
        }

        out.b = if *self { 1 } else { 0 };
        Ok(())
    }

    unsafe fn from_data(value: &ss_plugin_state_data, type_id: FieldTypeId) -> Option<Self> {
        if type_id != FieldTypeId::Bool {
            return None;
        }

        Some(value.b != 0)
    }
}

impl StaticField for bool {
    const TYPE_ID: FieldTypeId = FieldTypeId::Bool;
}

impl TryFrom<DynamicFieldValue> for bool {
    type Error = anyhow::Error;

    fn try_from(value: DynamicFieldValue) -> Result<Self, Self::Error> {
        if let DynamicFieldValue::Bool(b) = value {
            Ok(b)
        } else {
            Err(anyhow::anyhow!(
                "Type mismatch, expected bool, got {:?}",
                value
            ))
        }
    }
}

impl seal::Sealed for CString {}

impl FieldValue for CString {
    fn to_data(
        &self,
        out: &mut ss_plugin_state_data,
        type_id: FieldTypeId,
    ) -> Result<(), anyhow::Error> {
        if type_id != FieldTypeId::String {
            anyhow::bail!("Type mismatch, requested {:?}, got string", type_id)
        }

        out.str_ = self.as_ptr();
        Ok(())
    }

    unsafe fn from_data(value: &ss_plugin_state_data, type_id: FieldTypeId) -> Option<Self> {
        if type_id != FieldTypeId::String {
            return None;
        }

        Some(CStr::from_ptr(value.str_).to_owned())
    }
}

impl StaticField for CString {
    const TYPE_ID: FieldTypeId = FieldTypeId::String;
}

impl TryFrom<DynamicFieldValue> for CString {
    type Error = anyhow::Error;

    fn try_from(value: DynamicFieldValue) -> Result<Self, Self::Error> {
        if let DynamicFieldValue::String(s) = value {
            Ok(s)
        } else {
            Err(anyhow::anyhow!(
                "Type mismatch, expected string, got {:?}",
                value
            ))
        }
    }
}
