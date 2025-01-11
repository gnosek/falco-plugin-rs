#[cfg(feature = "thread-safe-tables")]
mod thread_safe {
    use std::cell::Cell;

    #[derive(Default)]
    pub struct PerThreadCell<T: Send + Default>(thread_local::ThreadLocal<Cell<T>>);

    impl<T: Send + Default> PerThreadCell<T> {
        pub fn replace(&self, value: T) -> T {
            self.0.get_or(Default::default).replace(value)
        }
    }
}

#[cfg(feature = "thread-safe-tables")]
pub use thread_safe::PerThreadCell;

#[cfg(not(feature = "thread-safe-tables"))]
pub use std::cell::Cell as PerThreadCell;
