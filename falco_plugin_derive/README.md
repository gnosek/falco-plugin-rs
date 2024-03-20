# Derive macros for `falco_plugin`

This crate currently contains the derive macro for the [`falco_plugin::tables::TableValues`] trait. It is exported
as [`falco_plugin::TableValues`] and is documented there (since the generated code depends on `falco_plugin`,
adding example code to this crate would introduce a circular dependency).