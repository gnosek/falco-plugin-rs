# Falco plugin SDK

This crate provides a framework for writing [Falco](https://github.com/falcosecurity/falco)
plugins. There are several types of plugins available. Learn more about Falco plugins
and plugin types in the [Falco plugin documentation](https://falco.org/docs/plugins/).

Since Falco plugins are distributed as shared libraries, they must be built
with `crate_type = ["dylib"]`.

All plugins must implement the base plugin trait (see [`base`]) and at least one of the plugin
capabilities.

**Note**: due to the structure of the Falco plugin API, there can be only one plugin per shared
library, though that plugin can implement multiple capabilities, as described below.

### Event sourcing plugins

Source plugins are used to generate events. The implementation comes in two parts:

1. An implementation of [`source::SourcePlugin`] on the plugin type, which mostly serves
   to create a plugin instance
2. A type implementing [`source::SourcePluginInstance`], which does the actual event generation

To register your plugin's event sourcing capability, pass it to the [`source_plugin!`] macro.

See `samples/source_plugin.rs` for an example implementation.

### Field extraction plugins

Field extraction plugins add extra fields to be used in rule matching and rule output. Each
field has a name, type and a function or method that returns the actual extracted data.
Extraction plugins are created by implementing the [`extract::ExtractPlugin`] trait.

See `samples/extract_plugin.rs` for an example implementation.

### Event parsing plugins

Event parsing plugins are invoked on every event (modulo some filtering) and can be used to
maintain some state across events, e.g. for extraction plugins our source plugins to return
later. They are created by implementing [`parse::ParsePlugin`] and calling [`parse_plugin!`]
with the plugin type.

See `samples/parse_plugin.rs` for an example implementation.

### Asynchronous event plugins

Asynchronous event plugins can be used to inject events outside the flow of the main event loop,
for example from a separate thread. They are created by implementing [`async_event::AsyncEventPlugin`]
and calling [`async_event_plugin!`] with the plugin type.

See `samples/async_plugin.rs` for an example implementation.
