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

    let (dynamic_field_get, dynamic_field_set) = match (static_only, dynamic_fields.len()) {
        (false, 0) | (true, 1) => {
            return TokenStream::from(
                syn::Error::new(
                    name.span(),
                    "Struct must have exactly one #[dynamic] field or be marked as #[static_only]",
                )
                .to_compile_error(),
            );
        }
        (true, 0) => (
            quote!(Err(::falco_plugin::FailureReason::NotSupported)),
            quote!(Err(::falco_plugin::FailureReason::NotSupported)),
        ),
        (false, 1) => {
            let dynamic_field_name = dynamic_fields[0].ident.as_ref().unwrap();
            (
                quote!(::falco_plugin::tables::TableValues::get(&self.#dynamic_field_name, key, type_id, out)),
                quote!(self.#dynamic_field_name.set(key, value)),
            )
        }
        _ => {
            return TokenStream::from(
                syn::Error::new(
                    dynamic_fields[1].span(),
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

    let static_fields = visible_static_fields.clone().map(|f| {
        let readonly = f.attrs.iter().any(|a| a.meta.path().is_ident(&readonly));
        let mut name = f.ident.as_ref().unwrap().to_string();
        name.push('\0');
        let ty = &f.ty;
        let name = proc_macro2::Literal::c_string(
            std::ffi::CStr::from_bytes_with_nul(name.as_bytes()).unwrap(),
        );
        quote!( ( #name, <#ty as ::falco_plugin::tables::StaticField>::TYPE_ID, #readonly) )
    });

    let static_field_gets = visible_static_fields.clone().enumerate().map(|(i, f)| {
        let name = f.ident.as_ref().unwrap();
        quote!(#i => self.#name.to_data(out, type_id).ok_or(::falco_plugin::FailureReason::Failure))
    });

    let static_field_sets = visible_static_fields.clone().enumerate().map(|(i, f)| {
        let name = f.ident.as_ref().unwrap();
        quote!(#i => Ok(self.#name = value.try_into()?))
    });

    let has_dynamic_fields = !static_only;
    quote!(
        impl ::falco_plugin::tables::TableValues for #name {
            const STATIC_FIELDS: &'static [(&'static ::std::ffi::CStr, ::falco_plugin::tables::FieldTypeId, bool)] = &[
                #(#static_fields,)*
            ];
            const HAS_DYNAMIC_FIELDS: bool = #has_dynamic_fields;

            fn get(
                &self,
                key: usize,
                type_id: ::falco_plugin::tables::FieldTypeId,
                out: &mut ::falco_plugin::api::ss_plugin_state_data,
            ) -> Result<(), ::falco_plugin::FailureReason> {
                use ::falco_plugin::tables::TableValues;
                use ::falco_plugin::tables::FieldValue;
                match key {
                    #(#static_field_gets,)*
                    _ => #dynamic_field_get,
                }
            }

            fn set(&mut self, key: usize, value: ::falco_plugin::tables::DynamicFieldValue) -> Result<(), ::falco_plugin::FailureReason> {
                use ::falco_plugin::tables::TableValues;
                use ::falco_plugin::tables::FieldValue;
                match key {
                    #(#static_field_sets,)*
                    _ => #dynamic_field_set,
                }
            }
        }
    )
    .into()
}
