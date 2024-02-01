use anyhow::Error;
use falco_event::type_id::TypeId;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use falco_plugin_api::{ss_plugin_event_input, ss_plugin_extract_field};

use crate::extract::{Extract, ExtractFieldRequestArg};
use crate::plugin::extract::{ExtractField, ExtractPlugin};
use crate::plugin::storage::FieldStorageSession;
use crate::plugin::tables::table_reader::TableReader;

#[derive(Clone, Copy)]
pub enum ExtractArgType {
    None,
    OptionalIndex,
    OptionalKey,
    RequiredIndex,
    RequiredKey,
}

impl Serialize for ExtractArgType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ExtractArgType::None => serializer.serialize_none(),
            ExtractArgType::OptionalIndex => {
                let mut ss = serializer.serialize_struct("arg", 1)?;
                ss.serialize_field("isIndex", &true)?;
                ss.end()
            }
            ExtractArgType::OptionalKey => {
                let mut ss = serializer.serialize_struct("arg", 1)?;
                ss.serialize_field("isKey", &true)?;
                ss.end()
            }
            ExtractArgType::RequiredIndex => {
                let mut ss = serializer.serialize_struct("arg", 2)?;
                ss.serialize_field("isIndex", &true)?;
                ss.serialize_field("isRequired", &true)?;
                ss.end()
            }
            ExtractArgType::RequiredKey => {
                let mut ss = serializer.serialize_struct("arg", 2)?;
                ss.serialize_field("isKey", &true)?;
                ss.serialize_field("isRequired", &true)?;
                ss.end()
            }
        }
    }
}

pub fn serialize_field_type<S: Serializer>(f: &TypeId, serializer: S) -> Result<S::Ok, S::Error> {
    match f {
        TypeId::U64 => serializer.serialize_str("uint64"),
        TypeId::CharBuf => serializer.serialize_str("string"),
        TypeId::RelTime => serializer.serialize_str("reltime"),
        TypeId::AbsTime => serializer.serialize_str("abstime"),
        TypeId::Bool => serializer.serialize_str("bool"),
        TypeId::IPAddr => serializer.serialize_str("ipaddr"),
        TypeId::IPNet => serializer.serialize_str("ipnet"),
        _ => serializer.serialize_none(),
    }
}

pub trait Extractor<P: ExtractPlugin> {
    fn extract<'a>(
        &self,
        plugin: &'a mut P,
        context: &mut <P as ExtractPlugin>::ExtractContext,
        field: &mut ss_plugin_extract_field,
        event_input: &ss_plugin_event_input,
        tables: &TableReader,
        arg_type: ExtractArgType,
        storage: FieldStorageSession<'a>,
    ) -> Result<(), Error>;
}

impl<P, R, F> Extractor<P> for F
where
    P: ExtractPlugin,
    R: Extract,
    F: Fn(
        &mut P,
        &mut <P as ExtractPlugin>::ExtractContext,
        ExtractFieldRequestArg,
        &ss_plugin_event_input,
        &TableReader,
    ) -> Result<R, Error>,
{
    fn extract<'a>(
        &self,
        plugin: &'a mut P,
        context: &mut <P as ExtractPlugin>::ExtractContext,
        field: &mut ss_plugin_extract_field,
        event_input: &ss_plugin_event_input,
        tables: &TableReader,
        arg_type: ExtractArgType,
        storage: FieldStorageSession<'a>,
    ) -> Result<(), Error> {
        let result = self(
            plugin,
            context,
            unsafe { field.key(arg_type) }?,
            event_input,
            tables,
        )?;
        Ok(result.extract_to(field, storage)?)
    }
}

#[derive(Serialize)]
pub struct ExtractFieldInfo<P: ExtractPlugin> {
    pub name: &'static str,
    #[serde(rename = "type")]
    #[serde(serialize_with = "serialize_field_type")]
    pub field_type: TypeId,
    #[serde(rename = "isList")]
    pub is_list: bool,
    pub arg: ExtractArgType,
    #[serde(rename = "display")]
    pub display_name: Option<&'static str>,
    #[serde(rename = "desc")]
    pub description: &'static str,
    #[serde(skip)]
    pub func: &'static dyn Extractor<P>,
}

impl<P: ExtractPlugin> ExtractFieldInfo<P> {
    pub const fn with_arg(mut self, extract_arg_type: ExtractArgType) -> Self {
        self.arg = extract_arg_type;
        self
    }

    pub const fn with_display(mut self, display_name: &'static str) -> Self {
        self.display_name = Some(display_name);
        self
    }

    pub const fn with_description(mut self, description: &'static str) -> Self {
        self.description = description;
        self
    }
}

pub const fn field<P, R, F>(name: &'static str, func: &'static F) -> ExtractFieldInfo<P>
where
    P: ExtractPlugin,
    R: Extract,
    F: Fn(
        &mut P,
        &mut <P as ExtractPlugin>::ExtractContext,
        ExtractFieldRequestArg,
        &ss_plugin_event_input,
        &TableReader,
    ) -> Result<R, Error>,
{
    ExtractFieldInfo {
        name,
        field_type: <R as Extract>::TYPE_ID,
        is_list: <R as Extract>::IS_LIST,
        arg: ExtractArgType::None,
        display_name: None,
        description: name,
        func: func as &'static dyn Extractor<P>,
    }
}
