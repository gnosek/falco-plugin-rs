use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::rc::Rc;

use crate::plugin::tables::data::{FieldTypeId, Key};
use crate::FailureReason;
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_state_data, ss_plugin_state_type, ss_plugin_table_fieldinfo,
};
use field_value::dynamic::DynamicFieldValue;
use field_value::traits::FieldValue;

pub mod field_value;
pub mod macros;
pub(super) mod wrappers;

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
pub struct DynamicTable<K: Key + Ord + Clone, V: TableValues = DynamicFieldValues> {
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
    type Key: Key;
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

impl<K: Key + Ord + Clone, V: TableValues> DynamicTable<K, V> {
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

impl<K: Key + Ord + Clone, V: TableValues> ExportedTable for DynamicTable<K, V> {
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
            read_only: read_only as ss_plugin_bool,
        });

        Some(field)
    }
}
