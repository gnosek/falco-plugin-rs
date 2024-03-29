/// # Storage for extracted fields
///
/// Since we only pass pointers across the FFI boundary, we need to hold on to the underlying
/// data even after the plugin API method returns. This means it cannot own the data (e.g. strings)
/// but needs to borrow them from an object with a longer lifetime.
///
/// This is that object. It's used in a wrapper struct (generally hidden from you, the plugin SDK
/// user) that lives as long as the plugin instance. The strings themselves are cleared earlier,
/// usually during the next API call, but that's long enough and it conforms to the API contract.
#[derive(Default)]
pub struct FieldStorage {
    byte_storage: Vec<Vec<u8>>,
    pointer_storage: Vec<Vec<*const u8>>,
}

pub struct FieldStorageSession<'a> {
    byte_storage: &'a mut Vec<Vec<u8>>,
    pointer_storage: &'a mut Vec<Vec<*const u8>>,
}

impl FieldStorage {
    pub(crate) fn start(&mut self) -> FieldStorageSession {
        self.byte_storage.clear();
        self.pointer_storage.clear();

        FieldStorageSession {
            byte_storage: &mut self.byte_storage,
            pointer_storage: &mut self.pointer_storage,
        }
    }
}

impl FieldStorageSession<'_> {
    pub(crate) fn get_byte_storage(&mut self) -> &mut Vec<u8> {
        self.byte_storage.push(Vec::new());
        self.byte_storage.last_mut().unwrap()
    }

    pub(crate) fn get_byte_and_pointer_storage(&mut self) -> (&mut Vec<u8>, &mut Vec<*const u8>) {
        self.byte_storage.push(Vec::new());
        self.pointer_storage.push(Vec::new());
        (
            self.byte_storage.last_mut().unwrap(),
            self.pointer_storage.last_mut().unwrap(),
        )
    }
}
