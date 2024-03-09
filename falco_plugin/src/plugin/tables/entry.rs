use crate::plugin::error::{AsResult, LastError};
use crate::plugin::tables::field::{FromData, FromDataTag, TypedTableField};
use crate::plugin::tables::key::ToData;
use crate::plugin::tables::table::TableError;
use falco_plugin_api::{
    ss_plugin_state_data, ss_plugin_table_entry_t, ss_plugin_table_reader_vtable_ext,
    ss_plugin_table_t, ss_plugin_table_writer_vtable_ext,
};
use std::mem::ManuallyDrop;

/// # A read-only accessor to a table entry
///
/// This type corresponds to a particular entry in a table.
///
/// See the [`TableInitInput` trait](`crate::base::TableInitInput`) for more details.
pub struct TableEntryReader {
    pub(crate) table: *mut ss_plugin_table_t,
    pub(crate) entry: *mut ss_plugin_table_entry_t,
    pub(crate) reader_vtable: *const ss_plugin_table_reader_vtable_ext,
    pub(crate) last_error: LastError,

    pub(crate) entry_value: ss_plugin_state_data,
}

impl TableEntryReader {
    //noinspection DuplicatedCode
    /// # Read the value of a field for a particular table entry
    ///
    /// Given a [field descriptor](`crate::tables::TypedTableField`), this method returns
    /// the value of that field for the entry it describes
    pub fn read_field<'a, V: FromDataTag + ?Sized>(
        &'a mut self,
        field: &'a TypedTableField<V>,
    ) -> Result<V::Actual<'a>, anyhow::Error> {
        if self.table != field.table {
            anyhow::bail!("Trying to access a field from another table")
        }
        unsafe {
            let read_entry_field = self
                .reader_vtable
                .as_ref()
                .and_then(|vt| vt.read_entry_field)
                .ok_or(TableError::BadVtable)?;
            read_entry_field(
                self.table,
                self.entry,
                field.field.cast_const(),
                (&mut self.entry_value) as *mut _,
            )
            .as_result_with_last_error(&self.last_error)?;

            Ok(V::Actual::from_data(&self.entry_value))
        }
    }

    pub(crate) fn with_writer(
        self,
        writer_vtable: *const ss_plugin_table_writer_vtable_ext,
    ) -> TableEntry {
        TableEntry {
            reader: ManuallyDrop::new(self),
            writer_vtable,
            from_reader: true,
        }
    }
}

impl Drop for TableEntryReader {
    fn drop(&mut self) {
        unsafe {
            if let Some(release_table_entry) = self
                .reader_vtable
                .as_ref()
                .and_then(|vt| vt.release_table_entry)
            {
                release_table_entry(self.table, self.entry)
            }
        }
    }
}

/// # A read-write accessor to a table entry
///
/// This type corresponds to a particular entry in a table.
///
/// See the [`TableInitInput` trait](`crate::base::TableInitInput`) for more details.
pub struct TableEntry {
    reader: ManuallyDrop<TableEntryReader>,
    writer_vtable: *const ss_plugin_table_writer_vtable_ext,

    // if from_reader, we have to call release_entry on drop,
    // otherwise destroy_entry
    from_reader: bool,
}

impl TableEntry {
    /// # Read the value of a field for a particular table entry
    ///
    /// Given a [field descriptor](`crate::tables::TypedTableField`), this method returns
    /// the value of that field for the entry it describes.
    pub fn read_field<'a, V: FromDataTag + ?Sized>(
        &'a mut self,
        field: &'a TypedTableField<V>,
    ) -> Result<V::Actual<'a>, anyhow::Error> {
        self.reader.read_field(field)
    }

    /// # Write the value of a field for a particular table entry
    ///
    /// Given a [field descriptor](`crate::tables::TypedTableField`), this method sets
    /// the value of that field for the entry it describes to `value`.
    pub fn write_field<V: FromDataTag + ?Sized>(
        &self,
        field: &TypedTableField<V>,
        value: V::Actual<'_>,
    ) -> Result<(), anyhow::Error> {
        if self.reader.table != field.table {
            anyhow::bail!("Trying to access a field from another table")
        }
        let value = value.to_data();
        let write_entry_field = unsafe {
            self.writer_vtable
                .as_ref()
                .and_then(|vt| vt.write_entry_field)
                .ok_or(TableError::BadVtable)?
        };
        unsafe {
            write_entry_field(
                self.reader.table,
                self.reader.entry,
                field.field.cast_const(),
                &value as *const _,
            )
        }
        .as_result_with_last_error(&self.reader.last_error)
    }
}

impl Drop for TableEntry {
    fn drop(&mut self) {
        if self.from_reader {
            unsafe { ManuallyDrop::drop(&mut self.reader) }
        } else {
            unsafe {
                if let Some(destroy_table_entry) = self
                    .writer_vtable
                    .as_ref()
                    .and_then(|vt| vt.destroy_table_entry)
                {
                    destroy_table_entry(self.reader.table, self.reader.entry)
                }
            }
        }
    }
}
