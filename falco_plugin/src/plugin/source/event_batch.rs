use falco_event::events::EventToBytes;

#[derive(Default, Debug)]
pub(crate) struct EventBatchStorage {
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

/// # An object that describes a batch of events
///
/// This is only available by reference, not by ownership, since the data needs to outlive
/// the plugin API call and is stored elsewhere (in a wrapper struct that's not exposed to
/// plugin developers)
#[derive(Debug)]
pub struct EventBatch<'a> {
    buf: &'a mut Vec<u8>,
    offsets: &'a mut Vec<usize>,
}

impl EventBatch<'_> {
    /// # Add an event to a batch
    ///
    /// The event can be any type, but please note that the framework may have different
    /// opinions on this. For example, only source plugins with the `syscall` source can generate
    /// events other than [`source::PluginEvent`](`crate::source::PluginEvent`)
    ///
    /// **Note**: to generate such events, you may use
    /// the [`source::SourcePluginInstance::plugin_event`](`crate::source::SourcePluginInstance::plugin_event`)
    /// helper method.
    pub fn add(&mut self, event: impl EventToBytes) -> std::io::Result<()> {
        let pos = self.buf.len();
        event.write(&mut *self.buf)?;

        self.offsets.push(pos);
        Ok(())
    }
}
