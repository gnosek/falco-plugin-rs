use crate::event_derive::{EventMetadata, Format, PayloadToBytes};
use crate::events::to_bytes::EventToBytes;
use crate::types::format::format_type;
use std::fmt::{Debug, Formatter};
use std::io::Write;

pub struct Event<T> {
    pub metadata: EventMetadata,
    pub params: T,
}

impl<T: Debug + Format<format_type::PF_NA>> Debug for Event<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.debug_struct("Event")
                .field("metadata", &self.metadata)
                .field("params", &self.params)
                .finish()
        } else {
            self.format(f)
        }
    }
}

impl<T: PayloadToBytes> EventToBytes for Event<T> {
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.params.write(&self.metadata, writer)
    }
}

impl<T, F> Format<F> for Event<T>
where
    EventMetadata: Format<F>,
    T: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        self.metadata.format(fmt)?;
        fmt.write_str(" ")?;
        self.params.format(fmt)
    }
}
