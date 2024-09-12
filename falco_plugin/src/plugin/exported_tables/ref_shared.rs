use refcell_lock_api::CellRwLock;
use std::sync::Arc;

/// like `RefCell<T>`
pub type RefCounted<T> = CellRwLock<T>;

/// like `Rc<RefCell<T>>`
pub type RefShared<T> = Arc<CellRwLock<T>>;

/// like `Rc<RefCell<T>> + RefMut<T>`
pub type RefGuard<T> = lock_api::ArcRwLockWriteGuard<refcell_lock_api::raw::CellRwLock, T>;

pub fn new_shared_ref<T>(inner: T) -> RefShared<T> {
    Arc::new(CellRwLock::new(inner))
}

pub fn new_counted_ref<T>(inner: T) -> RefCounted<T> {
    CellRwLock::new(inner)
}
