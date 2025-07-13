#![doc = include_str!("../README.md")]
#![deny(rustdoc::broken_intra_doc_links)]

use proc_macro::TokenStream;

mod any_event;
mod binary_payload;
mod helpers;

#[proc_macro_derive(EventPayload, attributes(event_payload, falco_event_crate))]
pub fn derive_event_payload(input: TokenStream) -> TokenStream {
    binary_payload::event_payload(input)
}

#[proc_macro_derive(AnyEvent, attributes(falco_event_crate))]
pub fn any_event(input: TokenStream) -> TokenStream {
    any_event::any_event(input)
}
