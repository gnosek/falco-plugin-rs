#![allow(non_camel_case_types)]

use std::ffi::CStr;
pub use std::net::IpAddr as PT_IPADDR;
pub use std::net::Ipv4Addr as PT_IPV4ADDR;
pub use std::net::Ipv6Addr as PT_IPV6ADDR;
use std::path::Path;
use std::time::{Duration, SystemTime};

pub use newtypes::Bool as PT_BOOL;
pub use newtypes::Errno as PT_ERRNO;
pub use newtypes::Fd as PT_FD;
pub use newtypes::Gid as PT_GID;
pub use newtypes::Pid as PT_PID;
pub use newtypes::Port as PT_PORT;
pub use newtypes::SigSet as PT_SIGSET;
pub use newtypes::SigType as PT_SIGTYPE;
pub use newtypes::SockFamily as PT_SOCKFAMILY;
pub use newtypes::SyscallId as PT_SYSCALLID;
pub use newtypes::Uid as PT_UID;

pub use crate::dynamic_params::*;
pub use crate::event_flags::*;
pub use crate::types::fd_list::FdList as PT_FDLIST;
pub use crate::types::net::ipnet as PT_IPNET;
pub use crate::types::net::ipv4net as PT_IPV4NET;
pub use crate::types::net::ipv6net as PT_IPV6NET;
pub use crate::types::net::sockaddr::SockAddr as PT_SOCKADDR;
pub use crate::types::net::socktuple::SockTuple as PT_SOCKTUPLE;
pub use crate::types::path::relative_path::RelativePath as PT_FSRELPATH;
use crate::types::primitive::newtypes;

pub type PT_INT8 = i8;
pub type PT_INT16 = i16;
pub type PT_INT32 = i32;
pub type PT_INT64 = i64;
pub type PT_UINT8 = u8;
pub type PT_UINT16 = u16;
pub type PT_UINT32 = u32;
pub type PT_UINT64 = u64;
pub type PT_CHARBUF = CStr;
pub type PT_BYTEBUF = [u8];
pub type PT_FSPATH = Path;
pub type PT_RELTIME = Duration;
pub type PT_ABSTIME = SystemTime;
pub type PT_CHARBUFARRAY<'a> = Vec<&'a CStr>;
pub type PT_CHARBUF_PAIR_ARRAY<'a> = Vec<(&'a CStr, &'a CStr)>;

// PT_DOUBLE = 33, /* this is a double precision floating point number. */ // this remains unimplemented
