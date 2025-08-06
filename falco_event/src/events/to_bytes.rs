use std::io::Write;

pub trait EventToBytes {
    fn binary_size(&self) -> usize;

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
