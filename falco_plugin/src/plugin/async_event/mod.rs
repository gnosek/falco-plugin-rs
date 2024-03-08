pub mod async_handler;
#[doc(hidden)]
pub mod wrappers;

use crate::base::Plugin;
use crate::plugin::async_event::async_handler::AsyncHandler;

pub trait AsyncEventPlugin: Plugin {
    const ASYNC_EVENTS: &'static [&'static str];
    const EVENT_SOURCES: &'static [&'static str];

    fn start_async(&mut self, handler: AsyncHandler) -> Result<(), anyhow::Error>;

    fn stop_async(&mut self) -> Result<(), anyhow::Error>;
}
