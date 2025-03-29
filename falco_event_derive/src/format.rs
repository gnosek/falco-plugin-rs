use proc_macro2::Ident;
use quote::quote;

pub fn formatter_for(
    pt_type: &Ident,
    pf_type: &Ident,
    val_tt: proc_macro2::TokenStream,
    formatter_tt: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    match (pt_type.to_string().as_str(), pf_type.to_string().as_str()) {
        ("PT_BYTEBUF", "PF_HEX") => quote!(write!(#formatter_tt, "{:x?}", #val_tt)),
        (_, "PF_HEX") => quote!(::std::fmt::LowerHex::fmt(#val_tt, #formatter_tt)),
        (_, "PF_OCT") => quote!(::std::fmt::Octal::fmt(#val_tt, #formatter_tt)),
        _ => quote!(::std::fmt::Debug::fmt(#val_tt, #formatter_tt)),
    }
}
