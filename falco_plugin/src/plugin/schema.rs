use schemars::{schema_for, JsonSchema};
use serde::de::DeserializeOwned;
use std::ffi::{CStr, CString};
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SchemaError {
    #[error("JSON deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type SchemaResult<T> = Result<T, SchemaError>;

pub enum ConfigSchemaType {
    None,
    Json(&'static CStr),
}

/// A wrapper to mark a configuration schema as JSON-encoded
///
/// Using this type as the configuration type in your plugin automatically generates
/// the schema describing the configuration format.
#[derive(Debug)]
pub struct Json<T: JsonSchema + DeserializeOwned>(T);

impl<T: JsonSchema + DeserializeOwned> Json<T> {
    /// Extract the parsed configuration object from the JSON wrapper
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: JsonSchema + DeserializeOwned> Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: JsonSchema + DeserializeOwned> DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub trait ConfigSchema: Sized {
    fn get_schema() -> ConfigSchemaType;

    fn from_str(s: &str) -> SchemaResult<Self>;
}

impl<T: JsonSchema + DeserializeOwned> ConfigSchema for Json<T> {
    fn get_schema() -> ConfigSchemaType {
        static SCHEMA: OnceLock<CString> = OnceLock::new();
        if SCHEMA.get().is_none() {
            let schema = schema_for!(T);
            let schema = serde_json::to_string_pretty(&schema).unwrap();
            let schema = CString::new(schema.into_bytes()).unwrap();
            SCHEMA
                .set(schema)
                .expect("multiple plugins not supported in a single crate");
        }

        ConfigSchemaType::Json(SCHEMA.get().unwrap().as_c_str())
    }

    fn from_str(s: &str) -> SchemaResult<Self> {
        let target: T = serde_json::from_str(s)?;
        Ok(Json(target))
    }
}

impl ConfigSchema for String {
    fn get_schema() -> ConfigSchemaType {
        ConfigSchemaType::None
    }

    fn from_str(s: &str) -> SchemaResult<Self> {
        Ok(s.to_string())
    }
}

impl ConfigSchema for () {
    fn get_schema() -> ConfigSchemaType {
        ConfigSchemaType::None
    }

    fn from_str(_: &str) -> SchemaResult<Self> {
        Ok(())
    }
}
