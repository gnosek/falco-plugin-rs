use crate::plugin::exported_tables::field_value::traits::FieldValue;
use crate::plugin::tables::data::{FieldTypeId, Key};
use crate::tables::export::{DynamicField, DynamicFieldValue, DynamicFieldValues, Entry};
use crate::FailureReason;
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_state_data, ss_plugin_state_type, ss_plugin_table_fieldinfo,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::rc::Rc;

// TODO(sdk) maybe use tinyvec (here, for storage and for extractions)
/// # A table with dynamic fields only by default
///
/// An instance of this type can be exposed to other plugins via
/// [`tables::TablesInput::add_table`](`crate::tables::TablesInput::add_table`)
///
/// To create a table that includes static fields, pass a type that implements
/// [`Entry`] as the second generic parameter.
pub struct DynamicTable<K: Key + Ord + Clone, E: Entry = DynamicFieldValues> {
    name: &'static CStr,
    fields: BTreeMap<CString, Rc<DynamicField>>,
    field_descriptors: Vec<ss_plugin_table_fieldinfo>,
    data: BTreeMap<K, Rc<RefCell<E>>>,
}

impl<K: Key + Ord + Clone, E: Entry> DynamicTable<K, E> {
    /// Create a new table
    pub fn new(name: &'static CStr) -> Self {
        let mut table = Self {
            name,
            fields: Default::default(),
            field_descriptors: vec![],
            data: BTreeMap::new(),
        };

        for (name, field_type, read_only) in E::STATIC_FIELDS {
            table.add_field(name, *field_type, *read_only);
        }

        table
    }

    /// Return the table name.
    pub fn name(&self) -> &'static CStr {
        self.name
    }

    /// Return the number of entries in the table.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Get an entry corresponding to a particular key.
    pub fn lookup(&self, key: &K) -> Option<Rc<RefCell<E>>> {
        self.data.get(key).cloned()
    }

    /// Get the value for a field in an entry.
    pub fn get_field_value(
        &self,
        entry: &Rc<RefCell<E>>,
        field: &Rc<DynamicField>,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        let (type_id, index) = { (field.type_id, field.index) };

        entry.borrow().get(index, type_id, out)
    }

    /// Execute a closure on all entries in the table with read-only access.
    ///
    /// The iteration continues until all entries are visited or the closure returns false.
    // TODO(upstream) the closure cannot store away the entry but we could use explicit docs
    pub fn iterate_entries<F>(&mut self, mut func: F) -> bool
    where
        F: FnMut(&mut Rc<RefCell<E>>) -> bool,
    {
        for value in &mut self.data.values_mut() {
            if !func(value) {
                return false;
            }
        }

        true
    }

    /// Remove all entries from the table.
    pub fn clear(&mut self) {
        self.data.clear()
    }

    /// Erase an entry by key.
    pub fn erase(&mut self, key: &K) -> Option<Rc<RefCell<E>>> {
        self.data.remove(key)
    }

    /// Create a new table entry.
    ///
    /// This is a detached entry that can be later inserted into the table using [`DynamicTable::add`].
    pub fn create_entry() -> Rc<RefCell<E>> {
        Rc::new(RefCell::new(E::default()))
    }

    /// Attach an entry to a table key
    pub fn add(&mut self, key: &K, entry: Rc<RefCell<E>>) -> Option<Rc<RefCell<E>>> {
        // note: different semantics from data.insert: we return the *new* entry
        self.data.insert(key.clone(), entry);
        self.lookup(key)
    }

    /// Write a value to a field of an entry
    pub fn write(
        &self,
        entry: &mut Rc<RefCell<E>>,
        field: &Rc<DynamicField>,
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

    /// Return a list of fields as a slice of raw FFI objects
    pub fn list_fields(&mut self) -> &[ss_plugin_table_fieldinfo] {
        self.field_descriptors.as_slice()
    }

    /// Return a field descriptor for a particular field
    ///
    /// The requested `field_type` must match the actual type of the field
    pub fn get_field(&self, name: &CStr, field_type: FieldTypeId) -> Option<Rc<DynamicField>> {
        let field = self.fields.get(name)?;
        if field.type_id != field_type {
            return None;
        }
        Some(Rc::clone(field))
    }

    /// Add a new field to the table
    pub fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<Rc<DynamicField>> {
        if let Some(existing_field) = self.fields.get(name) {
            if existing_field.type_id == field_type && existing_field.read_only == read_only {
                return Some(Rc::clone(existing_field));
            }
            return None;
        }

        if !E::HAS_DYNAMIC_FIELDS {
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
