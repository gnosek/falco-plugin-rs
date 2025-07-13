use crate::helpers::{add_raw_event_lifetimes, get_crate_path};
use proc_macro2::Ident;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, DataEnum, Field, Fields, Generics};

fn the_field(fields: &Fields) -> Result<&Field, syn::Error> {
    match fields {
        Fields::Unnamed(unnamed) if unnamed.unnamed.len() == 1 => {
            Ok(unnamed.unnamed.first().unwrap())
        }
        _ => Err(syn::Error::new(
            fields.span(),
            "Only single unnamed fields are allowed",
        )),
    }
}

fn derive_debug_for_fields(variant_ident: &Ident, fields: &Fields) -> proc_macro2::TokenStream {
    if let Err(e) = the_field(fields) {
        return e.to_compile_error();
    }
    quote!(Self::#variant_ident(_0) => ::std::fmt::Debug::fmt(&_0, f),)
}

fn derive_binary_size_fields(
    crate_path: &proc_macro2::TokenStream,
    variant_ident: &Ident,
    fields: &Fields,
) -> proc_macro2::TokenStream {
    if let Err(e) = the_field(fields) {
        return e.to_compile_error();
    }
    quote!(Self::#variant_ident(_0) => #crate_path::events::PayloadToBytes::binary_size(_0),)
}

fn derive_payload_to_bytes_for_fields(
    crate_path: &proc_macro2::TokenStream,
    variant_ident: &Ident,
    fields: &Fields,
) -> proc_macro2::TokenStream {
    if let Err(e) = the_field(fields) {
        return e.to_compile_error();
    }
    quote!(Self::#variant_ident(_0) => #crate_path::events::PayloadToBytes::write(_0, metadata, writer),)
}

fn derive_try_from_raw_event_for_fields(
    crate_path: &proc_macro2::TokenStream,
    variant_ident: &Ident,
    fields: &Fields,
) -> proc_macro2::TokenStream {
    let field = match the_field(fields) {
        Ok(field) => field,
        Err(err) => return err.to_compile_error(),
    };
    let ty = &field.ty;

    quote!(<#ty as #crate_path::events::EventPayload>::ID =>
        Self::#variant_ident(<#ty as #crate_path::events::FromRawEvent>::parse(raw)?),
    )
}

fn variant_type(fields: &Fields) -> proc_macro2::TokenStream {
    let field = match the_field(fields) {
        Ok(field) => field,
        Err(err) => return err.to_compile_error(),
    };
    let ty = &field.ty;
    quote!(#ty)
}

fn derive_any_event(
    crate_path: &proc_macro2::TokenStream,
    name: &Ident,
    generics: &Generics,
    e: &DataEnum,
) -> proc_macro2::TokenStream {
    let fmts = e
        .variants
        .iter()
        .map(|variant| derive_debug_for_fields(&variant.ident, &variant.fields));

    let binary_size = e
        .variants
        .iter()
        .map(|variant| derive_binary_size_fields(crate_path, &variant.ident, &variant.fields));

    let to_bytes = e.variants.iter().map(|variant| {
        derive_payload_to_bytes_for_fields(crate_path, &variant.ident, &variant.fields)
    });

    let try_from = e.variants.iter().map(|variant| {
        derive_try_from_raw_event_for_fields(crate_path, &variant.ident, &variant.fields)
    });

    let variant_types = e
        .variants
        .iter()
        .map(|variant| variant_type(&variant.fields))
        .collect::<Vec<_>>();

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let (impl_ref_generics, ref_where_clause) =
        add_raw_event_lifetimes(name, generics, where_clause);

    quote!(
        impl #impl_generics ::std::fmt::Debug for #name #ty_generics #where_clause {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match self {
                    #(#fmts)*
                }
            }
        }

        impl #impl_generics #crate_path::events::PayloadToBytes for #name #ty_generics #where_clause {
            #[inline]
            fn binary_size(&self) -> usize {
                match self {
                    #(#binary_size)*
                }
            }

            #[inline]
            fn write<W: ::std::io::Write>(&self, metadata: &#crate_path::events::EventMetadata, writer: W) -> ::std::io::Result<()> {
                match self {
                    #(#to_bytes)*
                }
            }
        }

        impl #impl_generics #crate_path::events::AnyEventPayload for #name #ty_generics #where_clause {
            const SOURCES: &'static [Option<&'static str>] = &[
                #(<#variant_types as #crate_path::events::EventPayload>::SOURCE,)*
            ];
            const EVENT_TYPES: &'static [u16] = &[
                #(<#variant_types as #crate_path::events::EventPayload>::ID,)*
            ];
        }

        impl <#impl_ref_generics> #crate_path::events::FromRawEvent<'raw_event> for #name #ty_generics #ref_where_clause {
            #[inline]
            fn parse(raw: &#crate_path::events::RawEvent<'raw_event>) -> Result<Self, #crate_path::events::PayloadFromBytesError> {
                let any: Self = match raw.event_type {
                    #(#try_from)*
                    other => return Err(#crate_path::events::PayloadFromBytesError::UnsupportedEventType(other)),
                };
                Ok(any)
            }
        }
    )
}

pub fn any_event(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input: syn::DeriveInput = syn::parse(input).unwrap();

    let crate_path = match get_crate_path(&input.attrs) {
        Ok(path) => path,
        Err(e) => return e.into(),
    };

    match input.data {
        Data::Enum(e) => derive_any_event(&crate_path, &input.ident, &input.generics, &e).into(),
        _ => syn::Error::new(input.span(), "AnyEvent can only be derived for enums")
            .to_compile_error()
            .into(),
    }
}
