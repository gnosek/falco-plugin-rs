use anyhow::Error;
use std::cell::RefCell;
use std::ffi::CStr;
use std::rc::Rc;

/// Metadata
///
/// Metadata is basically a type related to some other type, so the interface here
/// is very limited (just a constructor). While all types used as table values have metadata,
/// its type is usually `()`. Only table-typed fields have richer metadata, which stores e.g.
/// the list of dynamic fields (that needs to be shared across all entries).
pub trait Metadata: Sized {
    /// Create a new metadata object
    fn new() -> Result<Self, anyhow::Error>;
}

impl Metadata for () {
    fn new() -> Result<Self, Error> {
        Ok(())
    }
}

impl<M: Metadata> Metadata for Rc<RefCell<M>> {
    fn new() -> Result<Self, anyhow::Error> {
        Ok(Rc::new(RefCell::new(M::new()?)))
    }
}

/// A trait implemented for types that have metadata
///
/// For almost all types, their metadata is `()`, but for tables it's a type that implements
/// `TableMetadata` and can be used to create a new instance of a table, using the same list
/// of dynamic fields.
pub trait HasMetadata: Sized {
    /// The metadata type
    type Metadata;

    /// Create a new instance, using the provided metadata
    fn new_with_metadata(tag: &'static CStr, meta: &Self::Metadata) -> Result<Self, Error>;
}

impl<T: HasMetadata> HasMetadata for Rc<RefCell<T>> {
    type Metadata = T::Metadata;

    fn new_with_metadata(tag: &'static CStr, meta: &Self::Metadata) -> Result<Self, Error> {
        Ok(Rc::new(RefCell::new(T::new_with_metadata(tag, meta)?)))
    }
}