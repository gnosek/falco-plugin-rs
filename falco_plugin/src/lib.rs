// #![warn(missing_docs)]
// #![deny(clippy::undocumented_unsafe_blocks)]
// reexport dependencies
pub use schemars;
pub use serde;

pub use falco_event::types::net::ipnet::IpNet;
pub use falco_plugin_api::ss_plugin_event_input;

pub use crate::plugin::error::FailureReason;
pub use crate::plugin::event::EventInput;

pub mod base {
    pub use falco_plugin_api::ss_plugin_init_input as InitInput;

    pub use crate::plugin::base::Plugin;
    pub use crate::plugin::schema::Json;
    pub use crate::plugin::tables::ffi::InitInput as TableInitInput;
}

pub mod extract {
    pub use falco_plugin_api::ss_plugin_event_input as EventInput;
    pub use falco_plugin_api::ss_plugin_field_extract_input as FieldExtractInput;

    pub use crate::plugin::extract::fields::Extract;
    pub use crate::plugin::extract::schema::field;
    pub use crate::plugin::extract::schema::{ExtractArgType, ExtractFieldInfo};
    pub use crate::plugin::extract::ExtractFieldRequestArg;
    pub use crate::plugin::extract::ExtractPlugin;
    pub use crate::plugin::storage::FieldStorage;
}

pub mod parse {
    pub use falco_plugin_api::ss_plugin_event_parse_input as ParseInput;

    pub use crate::plugin::parse::EventParseInput;
    pub use crate::plugin::parse::ParsePlugin;
}

pub mod async_event {
    pub use crate::plugin::async_event::async_handler::AsyncHandler;
    pub use crate::plugin::async_event::AsyncEventPlugin;
    pub use falco_event::events::PPME_ASYNCEVENT_E as AsyncEvent;
}

pub mod source {
    pub use crate::plugin::source::event_batch::EventBatch;
    pub use crate::plugin::source::event_batch::EventBatchStorage;
    pub use crate::plugin::source::open_params::{serialize_open_params, OpenParam};
    pub use crate::plugin::source::{ProgressInfo, SourcePlugin, SourcePluginInstance};
    pub use crate::strings::cstring_writer::CStringWriter;
    pub use falco_event::events::PPME_PLUGINEVENT_E as PluginEvent;
}

pub mod tables {
    pub use crate::plugin::exported_tables::DynamicField;
    pub use crate::plugin::exported_tables::DynamicFieldValue;
    pub use crate::plugin::exported_tables::ExportedTable;
    pub use crate::plugin::tables::field::TypedTableField;
    pub use crate::plugin::tables::table::TypedTable;
    pub use crate::plugin::tables::table_reader::TableReader;
}

mod plugin;
mod strings;

#[doc(hidden)]
pub mod internals {
    pub use falco_plugin_api::plugin_api;
    pub use falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS as SUCCESS;

    pub use crate::plugin::error::FfiResult;

    pub mod base {
        pub use crate::plugin::base::wrappers;
        pub use crate::plugin::base::PluginWrapper;
    }

    pub mod source {
        pub use falco_plugin_api::ss_plugin_event;

        pub use crate::plugin::source::wrappers;
        pub use crate::plugin::source::SourcePluginInstanceWrapper;
    }

    pub mod extract {
        pub use crate::plugin::extract::wrappers;
    }

    pub mod parse {
        pub use crate::plugin::parse::wrappers;
    }

    pub mod async_events {
        pub use crate::plugin::async_event::wrappers;
    }
}
