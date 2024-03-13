use std::io::Write;

pub trait EventToBytes {
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()>;
}

impl<'a> EventToBytes for &'a [u8] {
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self)
    }
}
