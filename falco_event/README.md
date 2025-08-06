# Falco events

This crate provides support for working with Falco events.

This crate provides a strongly typed representation of the Falco event schema, allowing you to
load and work with Falco events in a type-safe manner.

The events may come in multiple forms:

- a raw byte buffer, as received from the plugin API or an external source, using a data
  format compatible with the Falco libs ringbuffer scheme
- a [raw event](events::RawEvent), which contains some metadata about the event, but all
  parameters are available only as a series of byte buffers
- a [parsed event](events::Event), which deserializes the raw fields into a Rust data type
  (either an event-specific type, or a generic enum encompassing all known event types)

**Note**: This crate does not provide the strongly typed event types themselves. These are implemented in the
`falco_event_schema` crate. See the documentation for that crate for more information about working with
strongly typed events.

## Byte slice to raw event

To read an event from a `&[u8]` to a [`events::RawEvent`], use [`events::RawEvent::from`].
It does some basic sanity checking on the slice, but does *not* validate e.g., that all event
parameters are present and the event is not truncated.

There also exists [`events::RawEvent::from_ptr`], which is useful if all you have is a raw pointer,
but it's unsafe for two reasons:

- it dereferences a raw pointer, which is unsafe enough
- it determines the length of the memory to access based on the event header

This method creates a slice from the pointer (based on the discovered length) and passes it
to [`events::RawEvent::from`].

## Raw event to typed event

The building block to parse typed events is [`events::RawEvent::load`], which tries to load all event
parameters into a payload type `T` that implements the [`events::FromRawEvent`] trait. It depends on the payload
type to do the actual parsing.

See the `falco_event_schema` crate for the types corresponding to the Falco event schema and examples of how to use
them.

## Event (raw or typed) to byte buffer

There is a trait ([events::EventToBytes]) that writes a serialized form of an event to a writer
(i.e., a type that implements [std::io::Write], for example `Vec<u8>`).
