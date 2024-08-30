use crate::plugin::tables::data::Value;
use crate::plugin::tables::vtable::{TableReader, TableWriter};
use falco_plugin_api::{
    ss_plugin_rc, ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_state_data, ss_plugin_table_entry_t,
    ss_plugin_table_field_t, ss_plugin_table_t,
};

pub struct RawEntry {
    pub(crate) table: *mut ss_plugin_table_t,
    pub(crate) entry: *mut ss_plugin_table_entry_t,
    pub(crate) destructor:
        Option<unsafe extern "C" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t)>,
}

impl RawEntry {
    pub unsafe fn read_field<'a, T: Value + ?Sized>(
        &self,
        reader: &TableReader,
        field: *const ss_plugin_table_field_t,
    ) -> Option<T::Value<'a>> {
        let mut data = ss_plugin_state_data { u64_: 0 };
        if unsafe { (reader.read_entry_field)(self.table, self.entry, field, &mut data as *mut _) }
            != ss_plugin_rc_SS_PLUGIN_SUCCESS
        {
            None
        } else {
            Some(unsafe { T::from_data(&data) })
        }
    }

    pub unsafe fn write_field(
        &self,
        writer: &TableWriter,
        field: *const ss_plugin_table_field_t,
        val: &ss_plugin_state_data,
    ) -> ss_plugin_rc {
        (writer.write_entry_field)(self.table, self.entry, field, val as *const _)
    }
}

impl Drop for RawEntry {
    fn drop(&mut self) {
        unsafe {
            if let Some(dtor) = self.destructor {
                dtor(self.table, self.entry)
            }
        }
    }
}
