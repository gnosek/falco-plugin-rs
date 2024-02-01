use crate::ffi::{
    ppm_param_type_PT_ABSTIME, ppm_param_type_PT_BOOL, ppm_param_type_PT_BYTEBUF,
    ppm_param_type_PT_CHARBUF, ppm_param_type_PT_CHARBUFARRAY,
    ppm_param_type_PT_CHARBUF_PAIR_ARRAY, ppm_param_type_PT_DOUBLE, ppm_param_type_PT_DYN,
    ppm_param_type_PT_ENUMFLAGS16, ppm_param_type_PT_ENUMFLAGS32, ppm_param_type_PT_ENUMFLAGS8,
    ppm_param_type_PT_ERRNO, ppm_param_type_PT_FD, ppm_param_type_PT_FDLIST,
    ppm_param_type_PT_FLAGS16, ppm_param_type_PT_FLAGS32, ppm_param_type_PT_FLAGS8,
    ppm_param_type_PT_FSPATH, ppm_param_type_PT_FSRELPATH, ppm_param_type_PT_GID,
    ppm_param_type_PT_INT16, ppm_param_type_PT_INT32, ppm_param_type_PT_INT64,
    ppm_param_type_PT_INT8, ppm_param_type_PT_IPADDR, ppm_param_type_PT_IPNET,
    ppm_param_type_PT_IPV4ADDR, ppm_param_type_PT_IPV4NET, ppm_param_type_PT_IPV6ADDR,
    ppm_param_type_PT_IPV6NET, ppm_param_type_PT_L4PROTO, ppm_param_type_PT_MODE,
    ppm_param_type_PT_NONE, ppm_param_type_PT_PID, ppm_param_type_PT_PORT,
    ppm_param_type_PT_RELTIME, ppm_param_type_PT_SIGSET, ppm_param_type_PT_SIGTYPE,
    ppm_param_type_PT_SOCKADDR, ppm_param_type_PT_SOCKFAMILY, ppm_param_type_PT_SOCKTUPLE,
    ppm_param_type_PT_SYSCALLID, ppm_param_type_PT_UID, ppm_param_type_PT_UINT16,
    ppm_param_type_PT_UINT32, ppm_param_type_PT_UINT64, ppm_param_type_PT_UINT8,
};
use num_derive::FromPrimitive;

/// The various data types supported by the Falco plugin framework
///
/// Limited subsets can be used in various contexts:
/// - event parameters
/// - values extracted by extract plugins
/// - table key types
/// - table value types
#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum TypeId {
    None = ppm_param_type_PT_NONE,
    I8 = ppm_param_type_PT_INT8,
    I16 = ppm_param_type_PT_INT16,
    I32 = ppm_param_type_PT_INT32,
    I64 = ppm_param_type_PT_INT64,
    U8 = ppm_param_type_PT_UINT8,
    U16 = ppm_param_type_PT_UINT16,
    U32 = ppm_param_type_PT_UINT32,
    U64 = ppm_param_type_PT_UINT64,
    /// A printable buffer of bytes, NULL terminated
    CharBuf = ppm_param_type_PT_CHARBUF,
    /// A raw buffer of bytes not suitable for printing
    ByteBuf = ppm_param_type_PT_BYTEBUF,
    /// this is an INT64, but will be interpreted as an error code
    Errno = ppm_param_type_PT_ERRNO,
    /// A sockaddr structure, 1byte family + data
    SockAddr = ppm_param_type_PT_SOCKADDR,
    /// A sockaddr tuple, 1byte family + 12byte data + 12byte data
    SockTuple = ppm_param_type_PT_SOCKTUPLE,
    /// A file descriptor number, 64bit
    Fd = ppm_param_type_PT_FD,
    /// A pid/tid, 64bit
    Pid = ppm_param_type_PT_PID,
    /// A list of fds, 16bit count + count * (64bit fd + 16bit flags)
    FdList = ppm_param_type_PT_FDLIST,
    /// A string containing a relative or absolute file system path, null terminated
    FsPath = ppm_param_type_PT_FSPATH,
    /// A 16bit system call ID. Can be used as a key for the g_ppm_sc_names table.
    SyscallID = ppm_param_type_PT_SYSCALLID,
    /// An 8-bit signal number
    SigType = ppm_param_type_PT_SIGTYPE,
    /// A relative time. Seconds * 10^9  + nanoseconds. 64bit.
    RelTime = ppm_param_type_PT_RELTIME,
    /// An absolute time interval. Seconds from epoch * 10^9  + nanoseconds. 64bit.
    AbsTime = ppm_param_type_PT_ABSTIME,
    /// A TCP/UDP prt. 2 bytes.
    Port = ppm_param_type_PT_PORT,
    /// A 1 byte IP protocol type.
    L4Proto = ppm_param_type_PT_L4PROTO,
    /// A 1 byte socket family.
    SockFamily = ppm_param_type_PT_SOCKFAMILY,
    /// A boolean value, 4 bytes.
    Bool = ppm_param_type_PT_BOOL,
    /// A 4 byte raw IPv4 address.
    IPv4Addr = ppm_param_type_PT_IPV4ADDR,
    /// Type can vary depending on the context. Used for filter fields like evt.rawarg.
    Dyn = ppm_param_type_PT_DYN,
    /// this is an UINT8, but will be interpreted as 8 bit flags.
    Flags8 = ppm_param_type_PT_FLAGS8,
    /// this is an UINT16, but will be interpreted as 16 bit flags.
    Flags16 = ppm_param_type_PT_FLAGS16,
    /// this is an UINT32, but will be interpreted as 32 bit flags.
    Flags32 = ppm_param_type_PT_FLAGS32,
    /// this is an UINT32, MAX_UINT32 will be interpreted as no value.
    Uid = ppm_param_type_PT_UID,
    /// this is an UINT32, MAX_UINT32 will be interpreted as no value.
    Gid = ppm_param_type_PT_GID,
    /// this is a double precision floating point number.
    Double = ppm_param_type_PT_DOUBLE,
    /// sigset_t. I only store the lower UINT32 of it
    SigSet = ppm_param_type_PT_SIGSET,
    /// Pointer to an array of strings, exported by the user events decoder. 64bit. For internal use only.
    CharBufArray = ppm_param_type_PT_CHARBUFARRAY,
    /// Pointer to an array of string pairs, exported by the user events decoder. 64bit. For internal use only.
    CharbufPairArray = ppm_param_type_PT_CHARBUF_PAIR_ARRAY,
    /// An IPv4 network.
    IPv4Net = ppm_param_type_PT_IPV4NET,
    /// A 16 byte raw IPv6 address.
    IPv6Addr = ppm_param_type_PT_IPV6ADDR,
    /// An IPv6 network.
    IPv6Net = ppm_param_type_PT_IPV6NET,
    /// Either an IPv4 or IPv6 address. The length indicates which one it is.
    IPAddr = ppm_param_type_PT_IPADDR,
    /// Either an IPv4 or IPv6 network. The length indicates which one it is.
    IPNet = ppm_param_type_PT_IPNET,
    /// a 32 bit bitmask to represent file modes.
    Mode = ppm_param_type_PT_MODE,
    /// A path relative to a dirfd.
    FsRelPath = ppm_param_type_PT_FSRELPATH,
    /// this is an UINT8, but will be interpreted as an enum flag, ie: contiguous values flag.
    EnumFlags8 = ppm_param_type_PT_ENUMFLAGS8,
    /// this is an UINT16, but will be interpreted as an enum flag, ie: contiguous values flag.
    EnumFlags16 = ppm_param_type_PT_ENUMFLAGS16,
    /// this is an UINT32, but will be interpreted as an enum flag, ie: contiguous values flag.
    EnumFlags32 = ppm_param_type_PT_ENUMFLAGS32,
}
