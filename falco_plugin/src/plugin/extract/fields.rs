use num_derive::FromPrimitive;
use std::ffi::{c_void, CString};

use falco_event::fields::ToBytes;
use falco_plugin_api::{
    ss_plugin_extract_field, ss_plugin_field_type_FTYPE_ABSTIME, ss_plugin_field_type_FTYPE_BOOL,
    ss_plugin_field_type_FTYPE_IPADDR, ss_plugin_field_type_FTYPE_IPNET,
    ss_plugin_field_type_FTYPE_RELTIME, ss_plugin_field_type_FTYPE_STRING,
    ss_plugin_field_type_FTYPE_UINT64,
};

use crate::plugin::storage::FieldStorageSession;

#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum ExtractFieldTypeId {
    /// A 64bit unsigned integer.
    U64 = ss_plugin_field_type_FTYPE_UINT64,
    /// A printable buffer of bytes, NULL terminated
    String = ss_plugin_field_type_FTYPE_STRING,
    /// A relative time. Seconds * 10^9  + nanoseconds. 64bit.
    RelTime = ss_plugin_field_type_FTYPE_RELTIME,
    /// An absolute time interval. Seconds from epoch * 10^9  + nanoseconds. 64bit.
    AbsTime = ss_plugin_field_type_FTYPE_ABSTIME,
    /// A boolean value, 4 bytes.
    Bool = ss_plugin_field_type_FTYPE_BOOL,
    /// Either an IPv4 or IPv6 address. The length indicates which one it is.
    IpAddr = ss_plugin_field_type_FTYPE_IPADDR,
    /// Either an IPv4 or IPv6 network. The length indicates which one it is.
    /// The field encodes only the IP address, so this differs from IPADDR,
    /// from the way the framework perform runtime checks and comparisons.
    IpNet = ss_plugin_field_type_FTYPE_IPNET,
}

pub trait Extract {
    const IS_LIST: bool;
    const TYPE_ID: ExtractFieldTypeId;

    fn extract_to(
        &self,
        req: &mut ss_plugin_extract_field,
        storage: FieldStorageSession,
    ) -> Result<(), std::io::Error>;
}

fn extract_direct_one<T: ToBytes>(
    val: &T,
    mut storage: FieldStorageSession<'_>,
) -> Result<(*mut c_void, u64), std::io::Error> {
    let mut buf = storage.get_byte_storage();
    val.write(&mut buf)?;
    Ok((buf.as_mut_ptr().cast(), 1))
}

fn extract_direct_many<T: ToBytes>(
    val: &[T],
    mut storage: FieldStorageSession<'_>,
) -> Result<(*mut c_void, u64), std::io::Error> {
    let mut buf = storage.get_byte_storage();
    for item in val.iter() {
        item.write(&mut buf)?;
    }
    Ok((buf.as_mut_ptr().cast(), val.len() as u64))
}

fn extract_indirect_one<T: ToBytes>(
    val: &T,
    mut storage: FieldStorageSession<'_>,
) -> Result<(*mut c_void, u64), std::io::Error> {
    let (mut buf, ptr_buf) = storage.get_byte_and_pointer_storage();
    val.write(&mut buf)?;

    ptr_buf.push(buf.as_ptr());
    Ok((ptr_buf.as_mut_ptr().cast(), 1))
}

fn extract_indirect_many<T: ToBytes>(
    val: &[T],
    mut storage: FieldStorageSession<'_>,
) -> Result<(*mut c_void, u64), std::io::Error> {
    let mut sizes = Vec::new();
    let (mut buf, ptr_buf) = storage.get_byte_and_pointer_storage();
    for item in val.iter() {
        item.write(&mut buf)?;
        sizes.push(item.binary_size());
    }

    let mut ptr = buf.as_ptr();
    for size in sizes {
        ptr_buf.push(ptr);
        ptr = unsafe { ptr.add(size) };
    }
    Ok((ptr_buf.as_mut_ptr().cast(), val.len() as u64))
}

macro_rules! extract_direct {
    ($ty:ty => $type_id:expr) => {
        impl Extract for $ty {
            const IS_LIST: bool = false;
            const TYPE_ID: ExtractFieldTypeId = $type_id;

            fn extract_to(
                &self,
                req: &mut ss_plugin_extract_field,
                storage: FieldStorageSession,
            ) -> Result<(), std::io::Error> {
                let (buf, len) = extract_direct_one(self, storage)?;
                req.res.u64_ = buf as *mut _;
                req.res_len = len;
                Ok(())
            }
        }

        impl Extract for Vec<$ty> {
            const IS_LIST: bool = true;
            const TYPE_ID: ExtractFieldTypeId = $type_id;

            fn extract_to(
                &self,
                req: &mut ss_plugin_extract_field,
                storage: FieldStorageSession,
            ) -> Result<(), std::io::Error> {
                let (buf, len) = extract_direct_many(self.as_slice(), storage)?;
                req.res.u64_ = buf as *mut _;
                req.res_len = len;
                Ok(())
            }
        }
    };
}

extract_direct!(u64 => ExtractFieldTypeId::U64);

impl Extract for CString {
    const IS_LIST: bool = false;
    const TYPE_ID: ExtractFieldTypeId = ExtractFieldTypeId::String;

    fn extract_to(
        &self,
        req: &mut ss_plugin_extract_field,
        storage: FieldStorageSession,
    ) -> Result<(), std::io::Error> {
        let (buf, len) = extract_indirect_one(self, storage)?;
        req.res.u64_ = buf as *mut _;
        req.res_len = len;
        Ok(())
    }
}
impl Extract for Vec<CString> {
    const IS_LIST: bool = true;
    const TYPE_ID: ExtractFieldTypeId = ExtractFieldTypeId::String;

    fn extract_to(
        &self,
        req: &mut ss_plugin_extract_field,
        storage: FieldStorageSession,
    ) -> Result<(), std::io::Error> {
        let (buf, len) = extract_indirect_many(self, storage)?;
        req.res.u64_ = buf as *mut _;
        req.res_len = len;
        Ok(())
    }
}
