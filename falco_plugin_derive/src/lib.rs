#![doc = include_str!("../README.md")]
use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(TableValues, attributes(static_only, dynamic, readonly, hidden))]
pub fn derive_table_values(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let static_only = syn::Ident::new("static_only", input.span());
    let hidden = syn::Ident::new("hidden", input.span());
    let readonly = syn::Ident::new("readonly", input.span());
    let dynamic = syn::Ident::new("dynamic", input.span());

    let static_only = input
        .attrs
        .iter()
        .any(|a| a.meta.path().is_ident(&static_only));

    let syn::Data::Struct(data) = input.data else {
        return TokenStream::from(
            syn::Error::new(
                input.ident.span(),
                "Only structs with named fields can derive `TableValues`",
            )
            .to_compile_error(),
        );
    };

    let name = &input.ident;
    let syn::Fields::Named(fields) = data.fields else {
        return TokenStream::from(
            syn::Error::new(
                input.ident.span(),
                "Only structs with named fields can derive `TableValues`",
            )
            .to_compile_error(),
        );
    };

    let fields = fields.named;

    let dynamic_fields = fields
        .iter()
        .filter(|f| f.attrs.iter().any(|a| a.meta.path().is_ident(&dynamic)))
        .collect::<Vec<_>>();

    let dynamic_field = match (static_only, dynamic_fields.len()) {
        (true, 0) => None,
        (false, 1) => dynamic_fields[0].ident.as_ref(),
        _ => {
            return TokenStream::from(
                syn::Error::new(
                    name.span(),
                    "Struct must have exactly one #[dynamic] field or be marked as #[static_only]",
                )
                .to_compile_error(),
            );
        }
    };

    let visible_static_fields = fields.iter().filter(|f| {
        !f.attrs
            .iter()
            .any(|a| a.meta.path().is_ident(&hidden) || a.meta.path().is_ident(&dynamic))
    });

    let static_fields = visible_static_fields.clone().enumerate().map(|(i, f)| {
        let readonly = f.attrs.iter().any(|a| a.meta.path().is_ident(&readonly));
        let field_name = f.ident.as_ref().unwrap();
        let mut field_name_str = field_name.to_string();
        field_name_str.push('\0');
        let ty = &f.ty;
        let field_name_str = proc_macro2::Literal::c_string(
            std::ffi::CStr::from_bytes_with_nul(field_name_str.as_bytes()).unwrap(),
        );
        quote!( [#i] #field_name_str as #field_name: #ty; readonly = #readonly )
    });

    quote!(::falco_plugin::impl_export_table!(
        for #name;
        dynamic = #dynamic_field
        {
            #(#static_fields)*
        }
    );)
    .into()
}
