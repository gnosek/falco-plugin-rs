use crate::plugin::error::as_result::{AsResult, WithLastError};
use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::data::Value;
use crate::plugin::tables::entry::raw::RawEntry;
use crate::plugin::tables::vtable::{TableReader, TableWriter};
use crate::tables::Field;
use falco_plugin_api::ss_plugin_table_t;

pub(in crate::plugin::tables) mod raw;

/// # A read-only accessor to a table entry
///
/// This type corresponds to a particular entry in a table.
pub struct TableEntryReader {
    pub(crate) table: *mut ss_plugin_table_t,
    pub(crate) entry: RawEntry,
    pub(crate) reader_vtable: TableReader,
    pub(crate) last_error: LastError,
}

impl TableEntryReader {
    //noinspection DuplicatedCode
    /// # Read the value of a field for a particular table entry
    ///
    /// Given a [field descriptor](`Field`), this method returns
    /// the value of that field for the entry it describes
    pub fn read_field<'a, V: Value + ?Sized>(
        &'a mut self,
        field: &'a Field<V>,
    ) -> Result<V::Value<'a>, anyhow::Error> {
        if self.table != field.table {
            anyhow::bail!("Trying to access a field from another table")
        }
        unsafe {
            self.entry
                .read_field::<V>(&self.reader_vtable, field.field.field.cast_const())
                .ok_or_else(|| anyhow::anyhow!("Failed to read field"))
                .with_last_error(&self.last_error)
        }
    }

    pub(crate) fn with_writer(self, writer_vtable: TableWriter) -> TableEntry {
        TableEntry {
            reader: self,
            writer_vtable,
        }
    }
}

/// # A read-write accessor to a table entry
///
/// This type corresponds to a particular entry in a table.
pub struct TableEntry {
    reader: TableEntryReader,
    writer_vtable: TableWriter,
}

impl TableEntry {
    /// # Read the value of a field for a particular table entry
    ///
    /// Given a [field descriptor](`Field`), this method returns
    /// the value of that field for the entry it describes.
    pub fn read_field<'a, V: Value + ?Sized>(
        &'a mut self,
        field: &'a Field<V>,
    ) -> Result<V::Value<'a>, anyhow::Error> {
        self.reader.read_field(field)
    }

    /// # Write the value of a field for a particular table entry
    ///
    /// Given a [field descriptor](`Field`), this method sets
    /// the value of that field for the entry it describes to `value`.
    pub fn write_field<V: Value + ?Sized>(
        &self,
        field: &Field<V>,
        value: &V,
    ) -> Result<(), anyhow::Error> {
        if self.reader.table != field.table {
            anyhow::bail!("Trying to access a field from another table")
        }
        let value = value.to_data();
        unsafe {
            self.reader.entry.write_field(
                &self.writer_vtable,
                field.field.field.cast_const(),
                &value,
            )
        }
        .as_result()
        .with_last_error(&self.reader.last_error)
    }
}
