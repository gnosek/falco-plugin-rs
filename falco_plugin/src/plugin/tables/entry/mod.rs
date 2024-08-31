use crate::plugin::error::as_result::{AsResult, WithLastError};
use crate::plugin::tables::data::Value;
use crate::plugin::tables::field::Field;
use crate::plugin::tables::vtable::{TableReader, TableWriter};
use falco_plugin_api::ss_plugin_table_t;

pub(in crate::plugin::tables) mod raw;
use raw::RawEntry;

/// # An entry in a Falco plugin table
///
/// This type wraps an opaque pointer representing an entry in a table and allows individual
/// field access (given a [`Field`] reference).
///
/// You can add methods to this type using the `#[derive(TableMetadata)]` macro.
/// See the [module documentation](`crate::tables::import`) for details.
pub struct Entry {
    pub(in crate::plugin::tables) raw_entry: RawEntry,
    pub(in crate::plugin::tables) table: *mut ss_plugin_table_t,
}

impl crate::plugin::tables::traits::Entry for Entry {
    fn new(raw_entry: RawEntry, table: *mut ss_plugin_table_t) -> Self {
        Self { raw_entry, table }
    }

    fn into_raw(self) -> RawEntry {
        self.raw_entry
    }
}

impl Entry {
    /// Get a field value for this entry
    pub fn read_field<V: Value + ?Sized>(
        &self,
        reader: &TableReader,
        field: &Field<V>,
    ) -> Result<V::Value<'_>, anyhow::Error> {
        field.validator.check(self.table)?;
        unsafe {
            self.raw_entry
                .read_field::<V>(reader, field.field.field)
                .ok_or(anyhow::anyhow!("Could not read field value"))
                .with_last_error(&reader.last_error)
        }
    }

    /// Set a field value for this entry
    pub fn write_field<V: Value + ?Sized>(
        &self,
        writer: &TableWriter,
        field: &Field<V>,
        val: &V,
    ) -> Result<(), anyhow::Error> {
        field.validator.check(self.table)?;
        unsafe {
            self.raw_entry
                .write_field(writer, field.field.field, &val.to_data())
                .as_result()
                .with_last_error(&writer.last_error)
        }
    }
}
