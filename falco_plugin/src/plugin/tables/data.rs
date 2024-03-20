use falco_event::fields::TypeId;
use std::ffi::CStr;
use std::marker::PhantomData;

use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_state_data, ss_plugin_table_field_t, ss_plugin_table_t,
};

mod seal {
    pub trait Sealed {}
}

/// # A trait describing types usable as table keys and values
pub trait TableData: seal::Sealed {
    /// The Falco plugin type id of the data
    const TYPE_ID: TypeId;

    /// # Borrow from the raw FFI representation
    ///
    /// **Note**: this function only borrows the data and must return a reference.
    /// This means that the types implementing this trait must be repr(C) and compatible
    /// with the layout of `ss_plugin_state_data`.
    ///
    /// # Safety
    /// `data` must contain valid data of the correct type
    unsafe fn from_data(data: &ss_plugin_state_data) -> &Self;

    /// # Convert to the raw FFI representation
    ///
    /// **Note**: even though the signature specifies an owned value, this value technically
    /// still borrows from `self`, as it contains raw pointers (for string values)
    fn to_data(&self) -> ss_plugin_state_data;
}

macro_rules! impl_table_data_for_numeric_type {
    ($ty:ty => $field:ident: $type_id:expr) => {
        impl seal::Sealed for $ty {}
        impl TableData for $ty {
            const TYPE_ID: TypeId = $type_id;

            unsafe fn from_data(data: &ss_plugin_state_data) -> &Self {
                unsafe { &data.$field }
            }

            fn to_data(&self) -> ss_plugin_state_data {
                ss_plugin_state_data { $field: *self }
            }
        }
    };
}

impl_table_data_for_numeric_type!(u8 => u8_: TypeId::U8);
impl_table_data_for_numeric_type!(i8 => s8: TypeId::I8);
impl_table_data_for_numeric_type!(u16 => u16_: TypeId::U16);
impl_table_data_for_numeric_type!(i16 => s16: TypeId::I16);
impl_table_data_for_numeric_type!(u32 => u32_: TypeId::U32);
impl_table_data_for_numeric_type!(i32 => s32: TypeId::I32);
impl_table_data_for_numeric_type!(u64 => u64_: TypeId::U64);
impl_table_data_for_numeric_type!(i64 => s64: TypeId::I64);

/// # A boolean value to use in tables
///
/// The boolean type in the plugin API is defined as a 32-bit value, which does not
/// necessarily correspond to the Rust [`bool`] type. Since we borrow the actual
/// value, we cannot convert it on the fly to the native Rust type.
///
/// This type serves as a wrapper, exposing conversion methods to/from Rust bool.
#[repr(transparent)]
pub struct Bool(pub(crate) ss_plugin_bool);

impl From<bool> for Bool {
    fn from(value: bool) -> Self {
        Self(if value { 1 } else { 0 })
    }
}

impl From<Bool> for bool {
    fn from(value: Bool) -> Self {
        value.0 != 0
    }
}

impl seal::Sealed for Bool {}

impl TableData for Bool {
    const TYPE_ID: TypeId = TypeId::Bool;

    unsafe fn from_data(data: &ss_plugin_state_data) -> &Self {
        unsafe { std::mem::transmute(&data.b) }
    }

    fn to_data(&self) -> ss_plugin_state_data {
        ss_plugin_state_data { b: self.0 }
    }
}

impl seal::Sealed for CStr {}

impl TableData for CStr {
    const TYPE_ID: TypeId = TypeId::CharBuf;

    unsafe fn from_data(data: &ss_plugin_state_data) -> &CStr {
        unsafe { CStr::from_ptr(data.str_) }
    }

    fn to_data(&self) -> ss_plugin_state_data {
        ss_plugin_state_data {
            str_: self.as_ptr(),
        }
    }
}

/// # Table field descriptor
///
/// This struct wraps an opaque pointer from the Falco plugin API, representing a particular
/// field of a table, while also remembering which data type the field holds.
///
/// You probably won't need to construct any values of this type, but you will receive
/// them from [`tables::TypedTable<K>::get_field`](`crate::tables::TypedTable::get_field`)
pub struct TypedTableField<V: TableData + ?Sized> {
    pub(crate) field: *mut ss_plugin_table_field_t,
    pub(crate) table: *mut ss_plugin_table_t, // used only for validation at call site
    value_type: PhantomData<V>,
}

impl<V: TableData + ?Sized> TypedTableField<V> {
    pub(crate) fn new(field: *mut ss_plugin_table_field_t, table: *mut ss_plugin_table_t) -> Self {
        Self {
            field,
            table,
            value_type: PhantomData,
        }
    }
}
