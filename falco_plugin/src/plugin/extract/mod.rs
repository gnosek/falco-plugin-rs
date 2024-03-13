use std::ffi::{CStr, CString};

use thiserror::Error;

use falco_event::events::types::EventType;
use falco_plugin_api::ss_plugin_extract_field;

use crate::extract::{EventInput, ExtractArgType};
use crate::plugin::base::Plugin;
use crate::plugin::extract::schema::ExtractFieldInfo;
use crate::plugin::storage::FieldStorage;
use crate::plugin::tables::table_reader::TableReader;

pub mod fields;
pub mod schema;
#[doc(hidden)]
pub mod wrappers;

/// The actual argument passed to the extractor function
///
/// It is validated based on the [`ExtractFieldInfo`] definition (use [`ExtractFieldInfo::with_arg`]
/// to specify the expected argument type).
///
/// **Note**: this type describes the actual argument in a particular invocation.
/// For describing the type of arguments the extractor accepts, please see [`ExtractArgType`]`
pub enum ExtractFieldRequestArg<'a> {
    /// no argument, the extractor was invoked as plain `field_name`
    None,
    /// an integer argument, the extractor was invoked as e.g. `field_name[1]`
    Int(u64),
    /// a string argument, the extractor was invoked as e.g. `field_name[foo]`
    String(&'a CStr),
}

#[derive(Debug, Error)]
pub enum ArgError {
    #[error("required argument missing")]
    Missing,

    #[error("unexpected argument")]
    Unexpected,

    #[error("expected string argument")]
    ExpectedString,

    #[error("expected int argument")]
    ExpectedInt,
}

pub trait ExtractField {
    unsafe fn key_unchecked(&self) -> ExtractFieldRequestArg;

    unsafe fn key(&self, arg_type: ExtractArgType) -> Result<ExtractFieldRequestArg, ArgError> {
        let key = unsafe { self.key_unchecked() };
        match key {
            k @ ExtractFieldRequestArg::None => match arg_type {
                ExtractArgType::None => Ok(k),
                ExtractArgType::OptionalIndex => Ok(k),
                ExtractArgType::OptionalKey => Ok(k),
                ExtractArgType::RequiredIndex => Err(ArgError::Missing),
                ExtractArgType::RequiredKey => Err(ArgError::Missing),
            },
            k @ ExtractFieldRequestArg::Int(_) => match arg_type {
                ExtractArgType::None => Err(ArgError::Unexpected),
                ExtractArgType::OptionalIndex => Ok(k),
                ExtractArgType::OptionalKey => Err(ArgError::ExpectedString),
                ExtractArgType::RequiredIndex => Ok(k),
                ExtractArgType::RequiredKey => Err(ArgError::ExpectedString),
            },
            k @ ExtractFieldRequestArg::String(_) => match arg_type {
                ExtractArgType::None => Err(ArgError::Unexpected),
                ExtractArgType::OptionalIndex => Err(ArgError::ExpectedInt),
                ExtractArgType::OptionalKey => Ok(k),
                ExtractArgType::RequiredIndex => Err(ArgError::ExpectedInt),
                ExtractArgType::RequiredKey => Ok(k),
            },
        }
    }
}

impl ExtractField for ss_plugin_extract_field {
    unsafe fn key_unchecked(&self) -> ExtractFieldRequestArg {
        if self.arg_present == 0 {
            return ExtractFieldRequestArg::None;
        }

        if self.arg_key.is_null() {
            return ExtractFieldRequestArg::Int(self.arg_index);
        }

        unsafe { ExtractFieldRequestArg::String(CStr::from_ptr(self.arg_key)) }
    }
}

/// # Support for field extraction plugins
pub trait ExtractPlugin: Plugin + Sized
where
    Self: 'static,
{
    /// The set of event types supported by this plugin
    ///
    /// If empty, the plugin will get invoked for all event types, otherwise it will only
    /// get invoked for event types from this list.
    const EVENT_TYPES: &'static [EventType];
    /// The set of event sources supported by this plugin
    ///
    /// If empty, the plugin will get invoked for events coming from all sources, otherwise it will
    /// only get invoked for events from sources named in this list.
    ///
    /// **Note**: one notable event source is called `syscall`
    const EVENT_SOURCES: &'static [&'static str];

    /// The extraction context
    ///
    /// It might be useful if your plugin supports multiple fields, and they all share some common
    /// preprocessing steps. Instead of redoing the preprocessing for each field, intermediate
    /// results can be stored in the context for subsequent extractions (from the same event).
    ///
    /// If you do not need a context to share between extracting fields of the same event, use `()`
    /// as the type.
    type ExtractContext: Default + 'static;

    /// The actual list of extractable fields
    ///
    /// The required signature corresponds to a method like:
    /// ```
    /// use anyhow::Error;
    /// use falco_plugin::extract::{EventInput, ExtractFieldRequestArg};
    /// use falco_plugin::tables::TableReader;
    ///
    /// # type R = u32;
    /// # struct Plugin;
    /// # impl Plugin {
    /// fn extract_sample(
    ///     &mut self,
    ///     context: &mut (),
    ///     arg: ExtractFieldRequestArg,
    ///     event: &EventInput,
    ///     tables: &TableReader,
    /// ) -> Result<R, Error> {
    /// #   Ok(0)
    /// }
    /// # }
    ///
    /// ```
    /// where `R` is one of the following types or a [`Vec`] of them:
    /// - [`u32`]
    /// - [`u64`]
    /// - [`bool`]
    /// - [`CString`]
    ///
    /// The `context` may be shared between all extractions for a particular event.
    ///
    /// `arg` is the actual argument passed along with the field (see [`ExtractFieldRequestArg`])
    ///
    /// `event` is the event being processed (see [`EventInput`](`crate::EventInput`))
    ///
    /// `tables` is an interface to access tables exposed from Falco core and other plugins (see
    /// [`tables`](`crate::tables`))
    ///
    /// **Note**: while the returned field type is automatically determined based on the return type
    /// of the function, the argument type defaults to [`ExtractArgType::None`] and must be explicitly specified
    /// using [`ExtractFieldInfo::with_arg`] if the function expects an argument.
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>];

    /// Generate the field schema for the Falco plugin framework
    ///
    /// The default implementation inspects all fields from [`Self::EXTRACT_FIELDS`] and generates
    /// a JSON description in the format expected by the framework.
    fn get_fields() -> &'static CStr {
        static FIELD_SCHEMA: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
        if FIELD_SCHEMA.get().is_none() {
            let schema = serde_json::to_string_pretty(&Self::EXTRACT_FIELDS).unwrap();
            let schema =
                CString::new(schema.into_bytes()).expect("failed to add NUL to field schema");
            FIELD_SCHEMA
                .set(schema)
                .expect("multiple plugins not supported in a single crate");
        }
        FIELD_SCHEMA.get().unwrap().as_c_str()
    }

    /// Perform the actual field extraction
    ///
    /// The default implementation creates an empty context and loops over all extraction
    /// requests, invoking the relevant function to actually generate the field value.
    fn extract_fields<'a>(
        &'a mut self,
        event_input: &EventInput,
        table_reader: TableReader,
        fields: &mut [ss_plugin_extract_field],
        storage: &'a mut FieldStorage,
    ) -> Result<(), anyhow::Error> {
        let mut context = Self::ExtractContext::default();

        for req in fields {
            let info = Self::EXTRACT_FIELDS
                .get(req.field_id as usize)
                .ok_or_else(|| anyhow::anyhow!("field index out of bounds"))?;
            info.func.extract(
                self,
                &mut context,
                req,
                event_input,
                &table_reader,
                info.arg,
                storage.start(),
            )?;
        }
        Ok(())
    }
}
