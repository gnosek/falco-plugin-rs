pub mod async_handler;
#[doc(hidden)]
pub mod wrappers;

use crate::base::Plugin;
use crate::plugin::async_event::async_handler::AsyncHandler;

/// # Support for asynchronous event plugins
pub trait AsyncEventPlugin: Plugin {
    /// # Event names coming from this plugin
    ///
    /// This constant contains a list describing the name list of all asynchronous events
    /// that this plugin is capable of pushing into a live event stream. The framework rejects
    /// async events produced by a plugin if their name is not on the name list returned by this
    /// function.
    const ASYNC_EVENTS: &'static [&'static str];
    /// # Event sources to attach asynchronous events to
    ///
    /// This constant contains a list describing the event sources for which this plugin
    /// is capable of injecting async events in the event stream of a capture.
    ///
    /// This is optional--if NULL or an empty array, then async events produced by this plugin will
    /// be injected in the event stream of any data source.
    const EVENT_SOURCES: &'static [&'static str];

    /// # Start asynchronous event generation
    ///
    /// When this method is called, your plugin should start whatever background mechanism
    /// is necessary (e.g. spawn a separate thread) and use the [`AsyncHandler::emit`] method
    /// to inject events to the main event loop.
    ///
    /// **Note**: you must provide a mechanism to shut down the thread upon a call to [`AsyncEventPlugin::stop_async`].
    /// This may involve e.g. a [`std::sync::atomic::AtomicBool`] flag that's set by [`AsyncEventPlugin::stop_async`]
    /// and periodically checked by the thread.
    fn start_async(&mut self, handler: AsyncHandler) -> Result<(), anyhow::Error>;

    /// # Stop asynchronous event generation
    ///
    /// When this method is called, your plugin must stop the background mechanism started by
    /// [`AsyncEventPlugin::start_async`] and wait for it to finish (no calls to [`AsyncHandler::emit`]
    /// are permitted after this method returns).
    ///
    /// **Note**: [`AsyncEventPlugin::start_async`] can be called again, with a different [`AsyncHandler`].
    fn stop_async(&mut self) -> Result<(), anyhow::Error>;
}
