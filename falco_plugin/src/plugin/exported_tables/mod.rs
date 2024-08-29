use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::rc::Rc;

use falco_plugin_api::{ss_plugin_state_data, ss_plugin_state_type, ss_plugin_table_fieldinfo};

use crate::plugin::tables::data::{FieldTypeId, TableData};
use crate::tables::Bool;
use crate::FailureReason;

pub(super) mod wrappers;

mod seal {
    pub trait Sealed {}
}

/// Trait implemented for types that can be table fields (both static and containers for dynamic fields)
///
/// This trait is sealed, meaning you cannot add new implementations (the list is limited
/// by the Falco plugin API)
pub trait FieldValue: seal::Sealed + Sized {
    /// Store a C representation of `&self` in `out`
    ///
    /// This method must return `Err` (and do nothing) if `&self` cannot be represented
    /// as a value of type [`FieldTypeId`].
    fn to_data(
        &self,
        out: &mut ss_plugin_state_data,
        type_id: FieldTypeId,
    ) -> Result<(), anyhow::Error>;

    /// Load value from a C representation in `value`
    ///
    /// This method must return `None` (and do nothing) if `Self` cannot represent
    /// a value of type [`FieldTypeId`].
    ///
    /// # Safety
    /// `value` must be a valid reference with the union member described by [`FieldTypeId`] filled
    /// with valid data.
    unsafe fn from_data(value: &ss_plugin_state_data, type_id: FieldTypeId) -> Option<Self>;
}

/// Trait implemented for types that can be static table fields
///
/// This trait is sealed, meaning you cannot add new implementations (the list is limited
/// by the Falco plugin API)
pub trait StaticField: FieldValue {
    /// The type id corresponding to the implementing type
    const TYPE_ID: FieldTypeId;
}

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

/// # A value actually stored in a dynamic table
///
/// This corresponds to `ss_plugin_state_data` in the plugin API.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum DynamicFieldValue {
    U8(u8),
    I8(i8),
    U16(u16),
    I16(i16),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    Bool(bool),
    String(CString),
}

impl seal::Sealed for DynamicFieldValue {}
impl FieldValue for DynamicFieldValue {
    fn to_data(
        &self,
        out: &mut ss_plugin_state_data,
        type_id: FieldTypeId,
    ) -> Result<(), anyhow::Error> {
        match self {
            DynamicFieldValue::U8(v) if type_id == FieldTypeId::U8 => out.u8_ = *v,
            DynamicFieldValue::I8(v) if type_id == FieldTypeId::I8 => out.s8 = *v,
            DynamicFieldValue::U16(v) if type_id == FieldTypeId::U16 => out.u16_ = *v,
            DynamicFieldValue::I16(v) if type_id == FieldTypeId::I16 => out.s16 = *v,
            DynamicFieldValue::U32(v) if type_id == FieldTypeId::U32 => out.u32_ = *v,
            DynamicFieldValue::I32(v) if type_id == FieldTypeId::I32 => out.s32 = *v,
            DynamicFieldValue::U64(v) if type_id == FieldTypeId::U64 => out.u64_ = *v,
            DynamicFieldValue::I64(v) if type_id == FieldTypeId::I64 => out.s64 = *v,
            DynamicFieldValue::Bool(v) if type_id == FieldTypeId::Bool => {
                out.b = if *v { 1 } else { 0 }
            }
            DynamicFieldValue::String(v) if type_id == FieldTypeId::String => {
                out.str_ = v.as_c_str().as_ptr()
            }
            _ => anyhow::bail!("Type mismatch, requested {:?}, got {:?}", type_id, self),
        };

        Ok(())
    }

    unsafe fn from_data(value: &ss_plugin_state_data, type_id: FieldTypeId) -> Option<Self> {
        match type_id {
            FieldTypeId::I8 => Some(Self::I8(value.s8)),
            FieldTypeId::I16 => Some(Self::I16(value.s16)),
            FieldTypeId::I32 => Some(Self::I32(value.s32)),
            FieldTypeId::I64 => Some(Self::I64(value.s64)),
            FieldTypeId::U8 => Some(Self::U8(value.u8_)),
            FieldTypeId::U16 => Some(Self::U16(value.u16_)),
            FieldTypeId::U32 => Some(Self::U32(value.u32_)),
            FieldTypeId::U64 => Some(Self::U64(value.u64_)),
            FieldTypeId::String => Some(Self::String(CStr::from_ptr(value.str_).to_owned())),
            FieldTypeId::Bool => Some(Self::Bool(value.b != 0)),
            _ => None,
        }
    }
}

/// # A descriptor for a dynamically added field
///
/// It knows its sequential ID (to look up fields by numbers, not by strings all the time)
/// and the type of stored data.
///
/// **Note**: the data is stored as [`DynamicFieldValue`] in any case, but the table enforces
/// the defined type on all incoming data.
pub struct DynamicField {
    index: usize,
    type_id: FieldTypeId,
    read_only: bool,
}

/// A table value type that only has dynamic fields
pub type DynamicFieldValues = BTreeMap<usize, DynamicFieldValue>;

/// # A trait for structs that can be stored as table values
///
/// For tables with dynamic fields only, it's easiest to use the [`DynamicFieldValues`] type
/// directly, for other types, you'll probably want to use the [`crate::TableValues`] derive macro.
pub trait TableValues: Default {
    /// A list of all static fields in this table
    const STATIC_FIELDS: &'static [(&'static CStr, FieldTypeId, bool)];

    /// True if this table supports adding custom fields, false otherwise
    const HAS_DYNAMIC_FIELDS: bool;

    /// Get field value by index
    ///
    /// This method must verify that `type_id` is correct for the underlying data type
    /// of the `key`th field and store the field's value in `out`.
    ///
    /// `key` will correspond to an entry in [`TableValues::STATIC_FIELDS`] or to a dynamic field
    /// (if it's larger than `STATIC_FIELDS.size()`)
    fn get(
        &self,
        key: usize,
        type_id: FieldTypeId,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error>;

    /// Set field value by index
    ///
    /// This method must verify that `type_id` is correct for the underlying data type
    /// and store `value` under the (numeric) `key`.
    ///
    /// `key` will correspond to an entry in [`TableValues::STATIC_FIELDS`] or to a dynamic field
    /// (if it's larger than `STATIC_FIELDS.size()`)
    fn set(&mut self, key: usize, value: DynamicFieldValue) -> Result<(), anyhow::Error>;
}

impl TableValues for DynamicFieldValues {
    const STATIC_FIELDS: &'static [(&'static CStr, FieldTypeId, bool)] = &[];
    const HAS_DYNAMIC_FIELDS: bool = true;

    fn get(
        &self,
        key: usize,
        type_id: FieldTypeId,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        if let Some((_, actual_type_id, _)) = Self::STATIC_FIELDS.get(key) {
            if type_id != *actual_type_id {
                return Err(anyhow::anyhow!(
                    "Type mismatch, requested {:?}, actual type is {:?}",
                    type_id,
                    actual_type_id
                ));
            };
        }

        let field = self
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("Dynamic field {} not found", key))?;

        field.to_data(out, type_id)
    }

    fn set(&mut self, key: usize, value: DynamicFieldValue) -> Result<(), anyhow::Error> {
        self.insert(key, value);
        Ok(())
    }
}

// TODO(sdk) maybe use tinyvec (here, for storage and for extractions)
/// # A table with dynamic fields only by default
///
/// An instance of this type can be exposed to other plugins via
/// [`crate::tables::TablesInput::add_table`]
///
/// To create a table that includes static fields, pass a type that implements
/// [`TableValues`] as the second generic parameter.
pub struct DynamicTable<K: TableData + Ord + Clone, V: TableValues = DynamicFieldValues> {
    name: &'static CStr,
    fields: BTreeMap<CString, Rc<DynamicField>>,
    field_descriptors: Vec<ss_plugin_table_fieldinfo>,
    data: BTreeMap<K, Rc<RefCell<V>>>,
}

/// # A table that can be exported to other plugins
///
/// Currently, there's no implementation of this trait other than [`DynamicTable`],
/// but once we have a derive macro, there should be no need to implement this trait
/// manually.
///
/// Since the trait specification uses [`Rc`], it's *not* thread-safe.
pub trait ExportedTable {
    /// The table key type.
    type Key: TableData;
    /// The table entry type, exposed over FFI as an opaque pointer.
    type Entry;
    /// The table field descriptor type, exposed over FFI as an opaque pointer.
    type Field;

    /// Return the table name.
    fn name(&self) -> &'static CStr;

    /// Return the number of entries in the table.
    fn size(&self) -> usize;

    /// Get an entry corresponding to a particular key.
    fn lookup(&self, key: &Self::Key) -> Option<Rc<Self::Entry>>;

    /// Get the value for a field in an entry.
    fn get_field_value(
        &self,
        entry: &Rc<Self::Entry>,
        field: &Rc<Self::Field>,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error>;

    /// Execute a closure on all entries in the table with read-only access.
    ///
    /// The iteration continues until all entries are visited or the closure returns false.
    fn iterate_entries<F>(&mut self, func: F) -> bool
    where
        F: FnMut(&mut Rc<Self::Entry>) -> bool; // TODO(upstream) the closure cannot store away the entry but we could use explicit docs

    /// Remove all entries from the table.
    fn clear(&mut self);

    /// Erase an entry by key.
    fn erase(&mut self, key: &Self::Key) -> Option<Rc<Self::Entry>>;

    /// Create a new table entry.
    ///
    /// This is a detached entry that can be later inserted into the table using [`ExportedTable::add`].
    fn create_entry() -> Rc<Self::Entry>;

    /// Attach an entry to a table key
    fn add(&mut self, key: &Self::Key, entry: Rc<Self::Entry>) -> Option<Rc<Self::Entry>>;

    /// Write a value to a field of an entry
    fn write(
        &self,
        entry: &mut Rc<Self::Entry>,
        field: &Rc<Self::Field>,
        value: &ss_plugin_state_data,
    ) -> Result<(), anyhow::Error>;

    /// Return a list of fields as a slice of raw FFI objects
    fn list_fields(&mut self) -> &[ss_plugin_table_fieldinfo];

    /// Return a field descriptor for a particular field
    ///
    /// The requested `field_type` must match the actual type of the field
    fn get_field(&self, name: &CStr, field_type: FieldTypeId) -> Option<Rc<Self::Field>>;

    /// Add a new field to the table
    fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<Rc<Self::Field>>;
}

impl<K: TableData + Ord + Clone, V: TableValues> DynamicTable<K, V> {
    /// Create a new table
    pub fn new(name: &'static CStr) -> Self {
        let mut table = Self {
            name,
            fields: Default::default(),
            field_descriptors: vec![],
            data: BTreeMap::new(),
        };

        for (name, field_type, read_only) in V::STATIC_FIELDS {
            table.add_field(name, *field_type, *read_only);
        }

        table
    }
}

impl<K: TableData + Ord + Clone, V: TableValues> ExportedTable for DynamicTable<K, V> {
    type Key = K;
    type Entry = RefCell<V>;
    type Field = DynamicField;

    fn name(&self) -> &'static CStr {
        self.name
    }

    fn size(&self) -> usize {
        self.data.len()
    }

    fn lookup(&self, key: &Self::Key) -> Option<Rc<Self::Entry>> {
        self.data.get(key).cloned()
    }

    fn get_field_value(
        &self,
        entry: &Rc<Self::Entry>,
        field: &Rc<Self::Field>,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        let (type_id, index) = { (field.type_id, field.index) };

        entry.borrow().get(index, type_id, out)
    }

    fn iterate_entries<F>(&mut self, mut func: F) -> bool
    where
        F: FnMut(&mut Rc<Self::Entry>) -> bool,
    {
        for value in &mut self.data.values_mut() {
            if !func(value) {
                return false;
            }
        }

        true
    }

    fn clear(&mut self) {
        self.data.clear()
    }

    fn erase(&mut self, key: &Self::Key) -> Option<Rc<Self::Entry>> {
        self.data.remove(key)
    }

    fn create_entry() -> Rc<Self::Entry> {
        Rc::new(RefCell::new(V::default()))
    }

    fn add(&mut self, key: &Self::Key, entry: Rc<Self::Entry>) -> Option<Rc<Self::Entry>> {
        // note: different semantics from data.insert: we return the *new* entry
        self.data.insert(key.clone(), entry);
        self.lookup(key)
    }

    fn write(
        &self,
        entry: &mut Rc<Self::Entry>,
        field: &Rc<Self::Field>,
        value: &ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        if field.read_only {
            return Err(anyhow::anyhow!("Field is read-only").context(FailureReason::NotSupported));
        }

        let (type_id, index) = { (field.type_id, field.index) };

        let value = unsafe {
            DynamicFieldValue::from_data(value, type_id).ok_or(anyhow::anyhow!(
                "Cannot store {:?} data (unsupported type)",
                type_id
            ))?
        };

        let mut entry = entry.borrow_mut();
        entry.set(index, value)
    }

    fn list_fields(&mut self) -> &[ss_plugin_table_fieldinfo] {
        self.field_descriptors.as_slice()
    }

    fn get_field(&self, name: &CStr, field_type: FieldTypeId) -> Option<Rc<Self::Field>> {
        let field = self.fields.get(name)?;
        if field.type_id != field_type {
            return None;
        }
        Some(Rc::clone(field))
    }

    fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<Rc<Self::Field>> {
        if let Some(existing_field) = self.fields.get(name) {
            if existing_field.type_id == field_type && existing_field.read_only == read_only {
                return Some(Rc::clone(existing_field));
            }
            return None;
        }

        if !V::HAS_DYNAMIC_FIELDS {
            return None;
        }

        let index = self.field_descriptors.len();
        let name = name.to_owned();

        let field = Rc::new(DynamicField {
            index,
            type_id: field_type,
            read_only,
        });
        self.fields.insert(name.clone(), Rc::clone(&field));

        self.field_descriptors.push(ss_plugin_table_fieldinfo {
            name: name.into_raw(),
            field_type: field_type as ss_plugin_state_type,
            read_only: Bool::from(read_only).0,
        });

        Some(field)
    }
}
