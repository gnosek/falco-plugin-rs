use std::ffi::{CStr, CString};

use thiserror::Error;

use falco_event::EventType;
use falco_plugin_api::ss_plugin_event_input;
use falco_plugin_api::ss_plugin_extract_field;

use crate::extract::ExtractArgType;
use crate::plugin::base::Plugin;
use crate::plugin::extract::schema::ExtractFieldInfo;
use crate::plugin::storage::FieldStorage;
use crate::plugin::tables::table_reader::TableReader;

pub mod fields;
pub mod schema;
pub mod wrappers;

pub enum ExtractFieldRequestArg<'a> {
    None,
    Int(u64),
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

pub trait ExtractPlugin: Plugin + Sized
where
    Self: 'static,
{
    const EVENT_TYPES: &'static [EventType];
    const EVENT_SOURCES: &'static [&'static str];
    type ExtractContext: 'static;

    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>];

    fn get_extract_context(&mut self) -> Self::ExtractContext;

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

    fn extract_fields<'a>(
        &'a mut self,
        event_input: &ss_plugin_event_input,
        table_reader: TableReader,
        fields: &mut [ss_plugin_extract_field],
        storage: &'a mut FieldStorage,
    ) -> Result<(), anyhow::Error> {
        let mut context = self.get_extract_context();

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
