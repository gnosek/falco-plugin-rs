use crate::helpers::{add_raw_event_lifetimes, get_crate_path};
use attribute_derive::FromAttr;
use proc_macro2::Ident;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_macro_input, Data, DataStruct, DeriveInput, Generics, WhereClause};

#[derive(FromAttr)]
#[from_attr(ident = event_payload)]
struct EventPayloadAttrs {
    length_type: syn::Type,
    code: syn::Expr,
    source: syn::Expr,
    from_bytes_bound: Option<syn::WhereClause>,
    to_bytes_bound: Option<syn::WhereClause>,
}

fn derive_to_bytes(
    crate_path: &proc_macro2::TokenStream,
    name: &Ident,
    s: &DataStruct,
    g: &Generics,
    attrs: &EventPayloadAttrs,
) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = g.split_for_impl();
    let length_type = &attrs.length_type;
    let event_code = &attrs.code;
    let members: Vec<_> = s.fields.members().collect();
    let num_fields = s.fields.members().count();

    let combined_where_clause: WhereClause;
    let where_clause = match (where_clause, &attrs.to_bytes_bound) {
        (None, None) => None,
        (Some(c), None) => Some(c),
        (None, Some(c)) => Some(c),
        (Some(c1), Some(c2)) => {
            let mut combined = c1.clone();
            combined.predicates.extend(c2.predicates.clone());
            combined_where_clause = combined;
            Some(&combined_where_clause)
        }
    };

    quote!(
        impl #impl_generics #crate_path::events::PayloadToBytes for #name #ty_generics #where_clause {
            #[inline]
            fn binary_size(&self) -> usize {
                use #crate_path::fields::ToBytes;

                let mut size = 26;
                size += ::std::mem::size_of::<#length_type>() * #num_fields;
                #(size += self.#members.binary_size();)*
                size
            }

            fn write<W: std::io::Write>(&self, metadata: &#crate_path::events::EventMetadata, mut writer: W) -> std::io::Result<()> {
                use #crate_path::events::EventPayload;
                use #crate_path::fields::ToBytes;

                const NUM_FIELDS: usize = #num_fields;
                let lengths: [#length_type; NUM_FIELDS] =
                    [#(#length_type::try_from(self.#members.binary_size()).unwrap()),*];

                metadata.write_header_with_lengths(#event_code, lengths, &mut writer)?;
                #(self.#members.write(&mut writer)?;)*
                Ok(())
            }
        }
    )
}

fn derive_from_bytes(
    crate_path: &proc_macro2::TokenStream,
    name: &Ident,
    s: &DataStruct,
    g: &Generics,
    attrs: &EventPayloadAttrs,
) -> proc_macro2::TokenStream {
    let (_impl_generics, ty_generics, where_clause) = g.split_for_impl();
    let length_type = &attrs.length_type;
    let event_code = &attrs.code;
    let members = s.fields.members();
    let (impl_ref_generics, mut ref_where_clause) = add_raw_event_lifetimes(name, g, where_clause);

    if let Some(c) = &attrs.from_bytes_bound {
        ref_where_clause.predicates.extend(c.predicates.clone());
    }

    quote!(
        impl <#impl_ref_generics> #crate_path::events::FromRawEvent<'raw_event> for #name #ty_generics #ref_where_clause {
            fn parse(raw: &#crate_path::events::RawEvent<'raw_event>) -> Result<Self, #crate_path::events::PayloadFromBytesError> {
            use #crate_path::events::PayloadFromBytesError;
                use #crate_path::events::RawEvent;
                use #crate_path::fields::FromBytes;
                use #crate_path::fields::FromBytesError;

                if raw.event_type != #event_code {
                    return Err(PayloadFromBytesError::TypeMismatch);
                }

                let mut params = raw.params::<#length_type>()?;
                Ok(#name {
                    #(#members: params.next_field().map_err(|e| PayloadFromBytesError::NamedField(stringify!(#members), e))?,)*
                })
            }
        }
    )
}

fn derive_meta(
    crate_path: &proc_macro2::TokenStream,
    name: &Ident,
    g: &Generics,
    attrs: &EventPayloadAttrs,
) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = g.split_for_impl();
    let event_code = &attrs.code;
    let event_source = &attrs.source;

    quote!(
        impl #impl_generics #crate_path::events::EventPayload for #name #ty_generics #where_clause {
            const ID: u16 = #event_code as u16;
            const SOURCE: Option<&'static str> = #event_source;
        }
    )
}

pub fn event_payload(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let attrs = match EventPayloadAttrs::from_attributes(&input.attrs) {
        Ok(attrs) => attrs,
        Err(err) => return err.to_compile_error().into(),
    };

    let crate_path = match get_crate_path(&input.attrs) {
        Ok(path) => path,
        Err(e) => return e.into(),
    };

    match input.data {
        Data::Struct(s) => {
            let from_bytes =
                derive_from_bytes(&crate_path, &input.ident, &s, &input.generics, &attrs);
            let to_bytes = derive_to_bytes(&crate_path, &input.ident, &s, &input.generics, &attrs);
            let meta = derive_meta(&crate_path, &input.ident, &input.generics, &attrs);

            quote!(
                #to_bytes
                #from_bytes
                #meta
            )
            .into()
        }
        _ => syn::Error::new(input.span(), "EventPayload can only be derived for structs")
            .to_compile_error()
            .into(),
    }
}
