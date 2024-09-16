# Falco plugin SDK

This crate provides a framework for writing [Falco](https://github.com/falcosecurity/falco)
plugins. There are several types of plugins available. Learn more about Falco plugins
and plugin types in the [Falco plugin documentation](https://falco.org/docs/plugins/).

All plugins must implement the base plugin trait (see [`base`]) and at least one of the plugin
capabilities.

## Linking

### Dynamically linked plugins

The typical way to distribute a Falco plugin is to build a shared library. To build a plugin as a shared
library, you need to:

1. Specify `crate_type = ["dylib"]` in the `[lib]` section of `Cargo.toml`,
2. Invoke [`plugin!`] and all the macros corresponding to the capabilities your plugin implements.

The general layout of your plugin code would be:

```ignore
struct MyPlugin { /* ... */ }

impl Plugin for MyPlugin { /* ... */ }

// one or more of the plugin capabilities:
impl SourcePlugin for MyPlugin { /* ... */ }

// generate actual plugin functions for Falco to use:
plugin!(MyPlugin);
// use the macros corresponding to the capabilities your plugin implements:
source_plugin!(MyPlugin);

// now you can call sinsp::register_plugin("/path/to/your.so")
// or get Falco to do it via the configuration file
```

#### Loading and configuring plugins in Falco

To load a plugin in Falco, you need to add them to the `plugins` and `load_plugins` sections in the config
file, for example:

```yaml
plugins:
  - name: my_plugin
    library_path: /path/to/libmyplugin.so
    init_config: ...
load_plugins:
  - my_plugin
```

The plugin name in `plugins.name` and in `load_plugins` must match [`base::Plugin::NAME`]. `init_config` is optional
and may contain either a string or a YAML object (which will be converted to JSON before passing it to your plugin).
In any case, the configuration must match [`base::Plugin::ConfigType`].

### Statically linked plugins

In some circumstances, you might prefer to link plugins statically into your application. This changes
the interface somewhat (instead of using predefined symbol names, you register your plugin by directly
passing a [`falco_plugin_api::plugin_api`] struct to `sinsp::register_plugin`).

For a statically linked plugin, you need to:

1. Specify `crate_type = ["staticlib"]` in the `[lib]` section of `Cargo.toml`,
2. Invoke the [`static_plugin!`] macro. You do not need to handle individual capabilities.

```ignore
struct MyPlugin { /* ... */ }

impl Plugin for MyPlugin { /* ... */ }

// one or more of the plugin capabilities:
impl SourcePlugin for MyPlugin { /* ... */ }

// generate the API structure for the plugin:
static_plugin!(MY_PLUGIN_API = MyPlugin);

// now you can call sinsp::register_plugin(&MY_PLUGIN_API) on the C++ side
```

Loading and configuring a statically linked plugin entirely depends on the application you're linking it into.

## Plugin capabilities

### Event sourcing plugins

Source plugins are used to generate events. The implementation comes in two parts:

1. An implementation of [`source::SourcePlugin`] on the plugin type, which mostly serves
   to create a plugin instance
2. A type implementing [`source::SourcePluginInstance`], which does the actual event generation

To register your plugin's event sourcing capability, pass it to the [`source_plugin!`] macro.

To create rules matching against events coming from your plugin, set the `source` field on a rule
to the value of [`source::SourcePlugin::EVENT_SOURCE`], for example (in `falco_rules.yaml`):

```yaml
- rule: match first 100 events from `my_plugin`
  desc: match first 100 events from `my_plugin`
  condition: evt.num <= 100
  output: %evt.plugininfo # evt.plugininfo comes from event_to_string()
  priority: CRITICAL
  source: my_plugin
```

### Field extraction plugins

Field extraction plugins add extra fields to be used in rule matching and rule output. Each
field has a name, type and a function or method that returns the actual extracted data.

Extraction plugins are created by implementing the [`extract::ExtractPlugin`] trait and calling
[`extract_plugin!`] with the plugin type.

Rules involving fields from extract plugins must match against the correct source (one of [
`extract::ExtractPlugin::EVENT_SOURCES`]).

### Event parsing plugins

Event parsing plugins are invoked on every event (modulo some filtering) and can be used to
maintain some state across events, e.g. for extraction plugins to return later.

Event parsing plugins are created by implementing [`parse::ParsePlugin`] and calling [`parse_plugin!`]
with the plugin type.

### Asynchronous event plugins

Asynchronous event plugins can be used to inject events outside the flow of the main event loop,
for example from a separate thread.

They are created by implementing [`async_event::AsyncEventPlugin`] and calling [`async_event_plugin!`]
with the plugin type.

## Logging in plugins

The SDK uses the [`log`] crate for logging, redirecting all messages to the Falco libs logger, so you can use
e.g. `log::info!` in your plugin without any explicit initialization. The log level defaults to `Trace`
in debug builds and to `Info` in release builds, but can be overridden by calling [`log::set_max_level`]
in your [plugin init method](`base::Plugin::new`).