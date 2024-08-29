use crate::plugin::exported_tables::entry::extensible::ExtensibleEntry;
use crate::plugin::exported_tables::entry::table_metadata::extensible::ExtensibleEntryMetadata;
use crate::plugin::exported_tables::entry::table_metadata::traits::TableMetadata;
use crate::plugin::exported_tables::entry::traits::Entry;
use crate::plugin::exported_tables::field_descriptor::{FieldDescriptor, FieldRef};
use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
use crate::plugin::exported_tables::metadata::HasMetadata;
use crate::plugin::exported_tables::metadata::Metadata;
use crate::plugin::exported_tables::vtable::Vtable;
use crate::plugin::tables::data::{FieldTypeId, Key};
use crate::FailureReason;
use falco_plugin_api::{ss_plugin_state_data, ss_plugin_table_fieldinfo};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::rc::Rc;

/// # A table exported to other plugins
///
/// An instance of this type can be exposed to other plugins via
/// [`tables::TablesInput::add_table`](`crate::tables::TablesInput::add_table`)
///
/// The generic parameters are: key type and entry type. The key type is anything
/// usable as a table key, while the entry type is a type that can be stored in the table.
/// You can obtain such a type by `#[derive]`ing Entry on a struct describing all the table fields.
///
/// Supported key types include:
/// - integer types (u8/i8, u16/i16, u32/i32, u64/i64)
/// - [`crate::tables::import::Bool`] (an API equivalent of bool)
/// - &CStr (spelled as just `CStr` when used as a generic argument)
///
/// See [`crate::tables::export`] for details.
///
/// Since the implementation uses [`Rc`], it's *not* thread-safe.
pub struct Table<K, E>
where
    K: Key + Ord + Clone,
    E: Entry,
    E::Metadata: TableMetadata,
{
    name: &'static CStr,
    field_descriptors: Vec<ss_plugin_table_fieldinfo>,
    metadata: Rc<RefCell<ExtensibleEntryMetadata<E::Metadata>>>,
    data: BTreeMap<K, Rc<RefCell<ExtensibleEntry<E>>>>,

    pub(in crate::plugin::exported_tables) vtable: RefCell<Option<Box<Vtable>>>,
}

impl<K, E> Debug for Table<K, E>
where
    K: Key + Ord + Clone + Debug,
    E: Entry + Debug,
    E::Metadata: TableMetadata + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table")
            .field("name", &self.name)
            .field("metadata", &self.metadata)
            .field("data", &self.data)
            .finish()
    }
}

impl<K, E> Table<K, E>
where
    K: Key + Ord + Clone,
    E: Entry,
    E::Metadata: TableMetadata,
{
    /// Create a new table using provided metadata
    ///
    /// This is only expected to be used by the derive macro.
    pub fn new_with_metadata(
        tag: &'static CStr,
        metadata: &Rc<RefCell<ExtensibleEntryMetadata<E::Metadata>>>,
    ) -> Result<Self, anyhow::Error> {
        let table = Self {
            name: tag,
            field_descriptors: vec![],
            metadata: metadata.clone(),
            data: BTreeMap::new(),

            vtable: RefCell::new(None),
        };

        Ok(table)
    }

    /// Create a new table
    pub fn new(name: &'static CStr) -> Result<Self, anyhow::Error> {
        Ok(Self {
            name,
            field_descriptors: vec![],
            metadata: Rc::new(RefCell::new(ExtensibleEntryMetadata::new()?)),
            data: BTreeMap::new(),

            vtable: RefCell::new(None),
        })
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
    pub fn lookup(&self, key: &K) -> Option<Rc<RefCell<ExtensibleEntry<E>>>> {
        self.data.get(key).cloned()
    }

    /// Get the value for a field in an entry.
    pub fn get_field_value(
        &self,
        entry: &Rc<RefCell<ExtensibleEntry<E>>>,
        field: &FieldDescriptor,
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
        F: FnMut(&mut Rc<RefCell<ExtensibleEntry<E>>>) -> bool,
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
    pub fn erase(&mut self, key: &K) -> Option<Rc<RefCell<ExtensibleEntry<E>>>> {
        self.data.remove(key)
    }

    /// Create a new table entry.
    ///
    /// This is a detached entry that can be later inserted into the table using [`Table::insert`].
    pub fn create_entry(&self) -> Result<Rc<RefCell<ExtensibleEntry<E>>>, anyhow::Error> {
        Ok(Rc::new(RefCell::new(ExtensibleEntry::new_with_metadata(
            self.name,
            &self.metadata,
        )?)))
    }

    /// Attach an entry to a table key
    pub fn insert(
        &mut self,
        key: &K,
        entry: Rc<RefCell<ExtensibleEntry<E>>>,
    ) -> Option<Rc<RefCell<ExtensibleEntry<E>>>> {
        // note: different semantics from data.insert: we return the *new* entry
        self.data.insert(key.clone(), entry);
        self.lookup(key)
    }

    /// Write a value to a field of an entry
    pub fn write(
        &self,
        entry: &mut Rc<RefCell<ExtensibleEntry<E>>>,
        field: &FieldDescriptor,
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
        self.field_descriptors.clear();
        self.field_descriptors.extend(self.metadata.list_fields());
        self.field_descriptors.as_slice()
    }

    /// Return a field descriptor for a particular field
    ///
    /// The requested `field_type` must match the actual type of the field
    pub fn get_field(&self, name: &CStr, field_type: FieldTypeId) -> Option<FieldRef> {
        self.metadata
            .get_field(name)
            .filter(|f| f.as_ref().type_id == field_type)
    }

    /// Add a new field to the table
    pub fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<FieldRef> {
        self.metadata.add_field(name, field_type, read_only)
    }
}
