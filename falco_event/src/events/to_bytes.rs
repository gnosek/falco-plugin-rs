use std::io::Write;

/// Trait for converting events to a byte representation.
///
/// This trait is implemented for types that can be serialized into a byte array representing
/// an event. It has the same methods as [`crate::events::payload::PayloadToBytes`], but is a separate
/// trait to disallow serializing raw payloads that are not events by mistake.
pub trait EventToBytes {
    /// Get the binary size of the event.
    fn binary_size(&self) -> usize;

    /// Write the event to a writer implementing `[std::io::Write]`.
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()>;
}

impl EventToBytes for &[u8] {
    #[inline]
    fn binary_size(&self) -> usize {
        self.len()
    }

    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self)
    }
}
