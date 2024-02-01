use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::ffi::{CStr, CString};

#[derive(Debug)]
pub enum OpenParam<'a> {
    Item {
        value: &'a str,
        desc: &'a str,
    },
    Seq {
        values: &'a [&'a str],
        desc: &'a str,
        separator: char,
    },
}

impl Serialize for OpenParam<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OpenParam::Item { value, desc } => {
                let mut ss = serializer.serialize_struct("param", 2)?;
                ss.serialize_field("value", value)?;
                ss.serialize_field("desc", desc)?;
                ss.end()
            }
            OpenParam::Seq {
                values,
                desc,
                separator,
            } => {
                let mut sep = [0u8; 4];
                let sep = separator.encode_utf8(sep.as_mut_slice());
                let value = values.join(sep);
                let mut ss = serializer.serialize_struct("param", 3)?;
                ss.serialize_field("value", value.as_str())?;
                ss.serialize_field("desc", desc)?;
                ss.serialize_field("separator", &separator)?;
                ss.end()
            }
        }
    }
}

pub fn serialize_open_params<'a>(
    params: &[OpenParam],
    storage: &'a mut CString,
) -> Result<&'a CStr, anyhow::Error> {
    let buf = serde_json::to_string_pretty(params)?;
    let mut buf = CString::new(buf)?;
    std::mem::swap(&mut buf, storage);
    Ok(storage.as_c_str())
}
