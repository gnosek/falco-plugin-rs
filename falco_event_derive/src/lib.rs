use proc_macro::TokenStream;

mod binary_payload;
mod dynamic_params;
mod event_flags;
mod event_info;

#[proc_macro_derive(BinaryPayload)]
pub fn derive_payload(input: TokenStream) -> TokenStream {
    binary_payload::derive_payload(input)
}

#[proc_macro]
pub fn event_info(input: TokenStream) -> TokenStream {
    event_info::event_info(input)
}

#[proc_macro]
pub fn event_flags(input: TokenStream) -> TokenStream {
    event_flags::event_flags(input)
}

#[proc_macro]
pub fn dynamic_params(input: TokenStream) -> TokenStream {
    dynamic_params::dynamic_params(input)
}
