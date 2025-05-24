use crate::helpers::get_crate_path;
use attribute_derive::FromAttr;
use proc_macro2::Ident;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_macro_input, Data, DataStruct, DeriveInput, Generics};

#[derive(FromAttr)]
#[from_attr(ident = event_payload)]
struct EventPayloadAttrs {
    length_type: syn::Type,
    code: syn::Expr,
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

    let field_sizes = s
        .fields
        .members()
        .map(|field| quote!(#length_type::try_from(self.#field.binary_size()).unwrap()));

    let field_writes = s
        .fields
        .members()
        .map(|field| quote!(self.#field.write(&mut writer)?;));

    let field_sizes_usize = s
        .fields
        .members()
        .map(|field| quote!(self.#field.binary_size()));

    let num_fields = s.fields.members().count();

    quote!(
        impl #impl_generics #crate_path::events::PayloadToBytes for #name #ty_generics #where_clause {
            #[inline]
            fn binary_size(&self) -> usize {
                use #crate_path::fields::ToBytes;

                let mut size = 26;
                size += ::std::mem::size_of::<#length_type>() * #num_fields;
                #(size += #field_sizes_usize;)*
                size
            }

            fn write<W: std::io::Write>(&self, metadata: &#crate_path::events::EventMetadata, mut writer: W) -> std::io::Result<()> {
                use #crate_path::events::EventPayload;
                use #crate_path::fields::ToBytes;

                const NUM_FIELDS: usize = #num_fields;
                let lengths: [#length_type; NUM_FIELDS] =
                    [#(#field_sizes),*];

                metadata.write_header_with_lengths(#event_code, lengths, &mut writer)?;
                #(#field_writes)*
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

    let field_reads = s.fields.members().map(|field| {
        quote!(
            let mut maybe_next_field = params.next().transpose()
                .map_err(|e| PayloadFromBytesError::NamedField(stringify!(#field), e))?;
            let #field = FromBytes::from_maybe_bytes(maybe_next_field.as_mut())
                .map_err(|e| PayloadFromBytesError::NamedField(stringify!(#field), e))?;
            if let Some(buf) = maybe_next_field {
                if !buf.is_empty() {
                    return Err(PayloadFromBytesError::NamedField(stringify!(#field), FromBytesError::LeftoverData));
                }
            }
        )
    });

    let field_names = s.fields.members();

    quote!(
        impl<'a> #crate_path::events::FromRawEvent<'a> for #name #ty_generics #where_clause {
            fn parse(raw: &#crate_path::events::RawEvent<'a>) -> Result<Self, #crate_path::events::PayloadFromBytesError> {
            use #crate_path::events::PayloadFromBytesError;
                use #crate_path::events::RawEvent;
                use #crate_path::fields::FromBytes;
                use #crate_path::fields::FromBytesError;

                if raw.event_type != #event_code {
                    return Err(PayloadFromBytesError::TypeMismatch);
                }

                let mut params = raw.params::<#length_type>()?;

                #(#field_reads)*

                Ok(#name {
                    #(#field_names),*
                })
            }
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

            quote!(
                #to_bytes
                #from_bytes
            )
            .into()
        }
        _ => syn::Error::new(input.span(), "EventPayload can only be derived for structs")
            .to_compile_error()
            .into(),
    }
}
