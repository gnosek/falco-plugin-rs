pub(super) mod wrappers;

use crate::plugin::tables::key::TableKey;
use crate::FailureReason;
use falco_event::type_id::TypeId;
use falco_plugin_api::{ss_plugin_state_data, ss_plugin_state_type, ss_plugin_table_fieldinfo};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::rc::Rc;

// ss_plugin_state_data, but type-safe and memory-safe
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

impl DynamicFieldValue {
    fn to_data(&self, out: &mut ss_plugin_state_data, type_id: TypeId) -> Option<()> {
        match self {
            DynamicFieldValue::U8(v) if type_id == TypeId::U8 => out.u8_ = *v,
            DynamicFieldValue::I8(v) if type_id == TypeId::I8 => out.s8 = *v,
            DynamicFieldValue::U16(v) if type_id == TypeId::U16 => out.u16_ = *v,
            DynamicFieldValue::I16(v) if type_id == TypeId::I16 => out.s16 = *v,
            DynamicFieldValue::U32(v) if type_id == TypeId::U32 => out.u32_ = *v,
            DynamicFieldValue::I32(v) if type_id == TypeId::I32 => out.s32 = *v,
            DynamicFieldValue::U64(v) if type_id == TypeId::U64 => out.u64_ = *v,
            DynamicFieldValue::I64(v) if type_id == TypeId::I64 => out.s64 = *v,
            DynamicFieldValue::Bool(v) if type_id == TypeId::Bool => out.b = if *v { 1 } else { 0 },
            DynamicFieldValue::String(v) if type_id == TypeId::CharBuf => {
                out.str_ = v.as_c_str().as_ptr()
            }
            _ => return None,
        };

        Some(())
    }

    unsafe fn from_data(value: &ss_plugin_state_data, type_id: TypeId) -> Option<Self> {
        match type_id {
            TypeId::I8 => Some(Self::I8(value.s8)),
            TypeId::I16 => Some(Self::I16(value.s16)),
            TypeId::I32 => Some(Self::I32(value.s32)),
            TypeId::I64 => Some(Self::I64(value.s64)),
            TypeId::U8 => Some(Self::U8(value.u8_)),
            TypeId::U16 => Some(Self::U16(value.u16_)),
            TypeId::U32 => Some(Self::U32(value.u32_)),
            TypeId::U64 => Some(Self::U64(value.u64_)),
            TypeId::CharBuf => Some(Self::String(CStr::from_ptr(value.str_).to_owned())),
            TypeId::Bool => Some(Self::Bool(value.b != 0)),
            _ => None,
        }
    }
}

pub struct DynamicField {
    index: usize,
    type_id: TypeId,
}

// TODO(sdk) consider predefined fields (with a derive)
// TODO(sdk) maybe use tinyvec (here, for storage and for extractions)
struct DynamicTable<K: TableKey + Ord + Clone> {
    name: CString,
    fields: BTreeMap<CString, Rc<RefCell<DynamicField>>>,
    field_descriptors: Vec<ss_plugin_table_fieldinfo>,
    data: BTreeMap<K, Rc<RefCell<BTreeMap<usize, DynamicFieldValue>>>>,
}

pub trait ExportedTable {
    type Key: TableKey;
    type Entry;
    type Field;

    fn name(&self) -> &CStr;
    fn size(&self) -> usize;
    fn lookup(&self, key: &Self::Key) -> Option<Rc<Self::Entry>>;
    fn get_field_value(
        &self,
        entry: &Rc<Self::Entry>,
        field: &Rc<Self::Field>,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), FailureReason>;
    fn iterate_entries<F>(&mut self, func: F) -> bool
    where
        F: FnMut(&mut Rc<Self::Entry>) -> bool; // TODO(upstream) the closure cannot store away the entry but we could use explicit docs

    fn clear(&mut self);
    fn erase(&mut self, key: &Self::Key) -> Option<Rc<Self::Entry>>;
    fn create_entry() -> Rc<Self::Entry>;
    fn add(&mut self, key: &Self::Key, entry: Rc<Self::Entry>) -> Option<Rc<Self::Entry>>;
    fn write(
        &self,
        entry: &mut Rc<Self::Entry>,
        field: &Rc<Self::Field>,
        value: &ss_plugin_state_data,
    ) -> Result<(), FailureReason>;

    fn list_fields(&mut self) -> &[ss_plugin_table_fieldinfo];
    fn get_field(&self, name: &CStr, field_type: TypeId) -> Option<Rc<Self::Field>>;
    fn add_field(&mut self, name: &CStr, field_type: TypeId) -> Option<Rc<Self::Field>>;
}

impl<K: TableKey + Ord + Clone> ExportedTable for DynamicTable<K> {
    type Key = K;
    type Entry = RefCell<BTreeMap<usize, DynamicFieldValue>>;
    type Field = RefCell<DynamicField>;

    fn name(&self) -> &CStr {
        self.name.as_c_str()
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
    ) -> Result<(), FailureReason> {
        let (type_id, index) = {
            let field = field.borrow();
            (field.type_id, field.index)
        };

        entry
            .borrow()
            .get(&index)
            .and_then(|val| val.to_data(out, type_id))
            .ok_or(FailureReason::Failure)
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
        Rc::new(RefCell::new(BTreeMap::new()))
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
    ) -> Result<(), FailureReason> {
        let (type_id, index) = {
            let field = field.borrow();
            (field.type_id, field.index)
        };

        let value =
            unsafe { DynamicFieldValue::from_data(value, type_id).ok_or(FailureReason::Failure)? };

        let mut entry = entry.borrow_mut();
        entry.insert(index, value);
        Ok(())
    }

    fn list_fields(&mut self) -> &[ss_plugin_table_fieldinfo] {
        self.field_descriptors.as_slice()
    }

    fn get_field(&self, name: &CStr, field_type: TypeId) -> Option<Rc<Self::Field>> {
        let field = self.fields.get(name)?;
        {
            let field = field.borrow();
            if field.type_id != field_type {
                return None;
            }
        }
        Some(Rc::clone(field))
    }

    fn add_field(&mut self, name: &CStr, field_type: TypeId) -> Option<Rc<Self::Field>> {
        if self.fields.get(name).is_some() {
            return None;
        }

        let index = self.field_descriptors.len();
        let name = name.to_owned();

        let field = Rc::new(RefCell::new(DynamicField {
            index,
            type_id: field_type,
        }));
        self.fields.insert(name.clone(), Rc::clone(&field));

        self.field_descriptors.push(ss_plugin_table_fieldinfo {
            name: name.into_raw(),
            field_type: field_type as ss_plugin_state_type,
            read_only: 0, // TODO(sdk) support read-only fields
        });

        Some(field)
    }
}
