# Falco plugin SDK

This crate provides a framework for writing [Falco](https://github.com/falcosecurity/falco)
plugins. There are several types of plugins available. Learn more about Falco plugins
and plugin types in the [Falco plugin documentation](https://falco.org/docs/plugins/).

## Dynamically linked plugins

The typical way to distribute a Falco plugin is to build a shared library. To build a plugin as a shared
library, you need to:

1. Specify `crate_type = ["dylib"]` in the `[lib]` section of `Cargo.toml`,
2. Invoke all the [macros](#macros) corresponding to the capabilities your plugin implements.

All plugins must implement the base plugin trait (see [`base`]) and at least one of the plugin
capabilities.

**Note**: due to the structure of the Falco plugin API, there can be only one plugin per shared
library, though that plugin can implement multiple capabilities, as described below.

## Statically linked plugins

In some circumstances, you might prefer to link plugins statically into your application. This changes
the interface somewhat (instead of using predefined symbol names, you register your plugin by directly
passing a [`falco_plugin_api::plugin_api`] struct to `sinsp::register_plugin`).

For a statically linked plugin, you need to:

1. Specify `crate_type = ["staticlib"]` in the `[lib]` section of `Cargo.toml`,
2. Export the plugin API under a name of your choice, for example:

```
use std::ffi::CStr;
use falco_plugin::base::{InitInput, Metric, Plugin};
use falco_plugin::static_plugin;

// define the type holding the plugin state
struct DummyPlugin;

// implement the base::Plugin trait
impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"sample-plugin-rs";
    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
    const CONTACT: &'static CStr = c"you@example.com";
    type ConfigType = ();

    fn new(input: &InitInput, config: Self::ConfigType)
        -> Result<Self, anyhow::Error> {
        Ok(DummyPlugin)
    }

    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
        Ok(())
    }

    fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
        []
    }
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);
```

**Note**: due to implementation limitations, there can be only one plugin per static library, though that
plugin can implement multiple capabilities, as described below. This limitation is more painful for static
libraries than for shared ones (since you could meaningfully ship multiple plugins in a static library)
and might be lifted in the future.

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
