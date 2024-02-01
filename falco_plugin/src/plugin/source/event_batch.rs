use falco_event::EventToBytes;

#[derive(Default, Debug)]
pub struct EventBatchStorage {
    buf: Vec<u8>,
    offsets: Vec<usize>,

    raw_pointers: Vec<*const u8>,
}

impl EventBatchStorage {
    pub fn start(&mut self) -> EventBatch {
        self.buf.clear();
        self.offsets.clear();

        EventBatch {
            buf: &mut self.buf,
            offsets: &mut self.offsets,
        }
    }

    pub fn get_raw_pointers(&mut self) -> (*const *const u8, usize) {
        if self.offsets.is_empty() {
            return (std::ptr::null(), 0);
        }

        self.raw_pointers.clear();
        self.raw_pointers.reserve(self.offsets.len());
        let base = self.buf.as_ptr();
        for offset in self.offsets.iter().copied() {
            self.raw_pointers.push(unsafe { base.add(offset) });
        }

        (self.raw_pointers.as_ptr(), self.offsets.len())
    }
}

pub struct EventBatch<'a> {
    buf: &'a mut Vec<u8>,
    offsets: &'a mut Vec<usize>,
}

impl EventBatch<'_> {
    pub fn add(&mut self, event: impl EventToBytes) -> std::io::Result<()> {
        let pos = self.buf.len();
        event.write(&mut self.buf)?;

        self.offsets.push(pos);
        Ok(())
    }
}
