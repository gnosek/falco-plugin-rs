use crate::event_info::{lifetime_type, LifetimeType};
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::{quote, ToTokens};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::{Brace, Bracket};
use syn::{braced, bracketed, parse_macro_input, LitInt, Token};

struct DynamicParamVariant {
    _brackets: syn::token::Bracket,
    discriminant: Ident,
    _eq: Token![=],
    _braces1: syn::token::Brace,
    _braces2: syn::token::Brace,
    _zero1: LitInt,
    _comma1: Token![,],
    field_type: Ident,
    _comma2: Token![,],
    _field_format: Ident,
    _comma3: Token![,],
    _zero2: LitInt,
    _comma4: Token![,],
    _zero3: LitInt,
}

impl Parse for DynamicParamVariant {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        let disc;
        let inner;
        Ok(DynamicParamVariant {
            _brackets: bracketed!(disc in input),
            discriminant: disc.parse()?,
            _eq: input.parse()?,
            _braces1: braced!(content in input),
            _braces2: braced!(inner in content),
            _zero1: inner.parse()?,
            _comma1: content.parse()?,
            field_type: content.parse()?,
            _comma2: content.parse()?,
            _field_format: content.parse()?,
            _comma3: content.parse()?,
            _zero2: content.parse()?,
            _comma4: content.parse()?,
            _zero3: content.parse()?,
        })
    }
}

impl DynamicParamVariant {
    fn unpack(
        &self,
    ) -> (
        &Ident,
        &Ident,
        proc_macro2::TokenStream,
        proc_macro2::TokenStream,
    ) {
        let disc = &self.discriminant;
        let ty = &self.field_type;
        let (field_ref, field_lifetime) = match lifetime_type(&self.field_type.to_string()) {
            LifetimeType::Ref => (quote!(&'a), proc_macro2::TokenStream::new()),
            LifetimeType::Generic => (proc_macro2::TokenStream::new(), quote!(<'a>)),
            LifetimeType::None => (
                proc_macro2::TokenStream::new(),
                proc_macro2::TokenStream::new(),
            ),
        };

        (disc, ty, field_ref, field_lifetime)
    }

    fn variant_definition(&self) -> proc_macro2::TokenStream {
        let (disc, ty, field_ref, field_lifetime) = self.unpack();

        quote!(#disc(#field_ref crate::event_field_type::#ty #field_lifetime))
    }

    fn variant_read(&self) -> proc_macro2::TokenStream {
        let (disc, ty, field_ref, field_lifetime) = self.unpack();

        quote!(crate::ffi:: #disc => {
            Ok(Self:: #disc(
                <#field_ref crate::event_field_type::#ty #field_lifetime as crate::event_derive::FromBytes>::from_bytes(buf)?
            ))
        })
    }

    fn variant_binary_size(&self) -> proc_macro2::TokenStream {
        let (disc, _, _, _) = self.unpack();

        quote!(Self:: #disc (val) => 1 + val.binary_size())
    }

    fn variant_write(&self) -> proc_macro2::TokenStream {
        let (disc, _, _, _) = self.unpack();

        quote!(Self:: #disc(val) => {
            writer.write_u8(crate::ffi::#disc as u8)?;
            crate::event_derive::ToBytes::write(val, writer)
        })
    }
}

struct DynamicParam {
    _const: Token![const],
    _struct: Token![struct],
    _type: Ident,
    name: Ident,
    _brackets: Bracket,
    _in_brackets: Ident,
    _eq: Token![=],
    _braces: Brace,
    items: Punctuated<DynamicParamVariant, Token![,]>,
}

impl Parse for DynamicParam {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let max;
        let items;
        Ok(DynamicParam {
            _const: input.parse()?,
            _struct: input.parse()?,
            _type: input.parse()?,
            name: input.parse()?,
            _brackets: bracketed!(max in input),
            _in_brackets: max.parse()?,
            _eq: input.parse()?,
            _braces: braced!(items in input),
            items: Punctuated::parse_terminated(&items)?,
        })
    }
}

impl ToTokens for DynamicParam {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = Ident::new(&format!("PT_DYN_{}", self.name), self.name.span());
        let variant_definitions = self.items.iter().map(|v| v.variant_definition());
        let variant_reads = self.items.iter().map(|v| v.variant_read());
        let variant_binary_size = self.items.iter().map(|v| v.variant_binary_size());
        let variant_write = self.items.iter().map(|v| v.variant_write());

        let wants_lifetime = !self.items.iter().all(|arg| {
            matches!(
                lifetime_type(&arg.field_type.to_string()),
                LifetimeType::None
            )
        });
        let lifetime = if wants_lifetime {
            quote!(<'a>)
        } else {
            proc_macro2::TokenStream::new()
        };

        quote!(
            #[allow(non_camel_case_types)]
            #[derive(Debug)]
            pub enum #name #lifetime {
                #(#variant_definitions,)*
            }

            impl #lifetime crate::event_derive::ToBytes for #name #lifetime {
                fn binary_size(&self) -> usize {
                    use crate::event_derive::ToBytes;
                    match self {
                        #(#variant_binary_size,)*
                    }
                }
                fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
                    use crate::event_derive::WriteBytesExt;

                    match self {
                        #(#variant_write)*
                    }
                }

                fn default_repr() -> impl crate::event_derive::ToBytes { crate::event_derive::NoDefault }
            }

            impl<'a> crate::event_derive::FromBytes<'a> for #name #lifetime {
                fn from_bytes(buf: &mut &'a [u8]) -> crate::event_derive::FromBytesResult<Self> {
                    use crate::event_derive::ReadBytesExt;
                    let variant = buf.read_u8()?;
                    match variant as u32 {
                        #(#variant_reads,)*
                        _ => Err(crate::event_derive::FromBytesError::InvalidDynDiscriminant),
                    }
                }
            }
        )
        .to_tokens(tokens);
    }
}

struct DynamicParams {
    params: Punctuated<DynamicParam, Token![;]>,
}

impl Parse for DynamicParams {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(DynamicParams {
            params: Punctuated::parse_terminated(input)?,
        })
    }
}

impl ToTokens for DynamicParams {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        for param in &self.params {
            param.to_tokens(tokens);
        }
    }
}

pub fn dynamic_params(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DynamicParams);
    input.into_token_stream().into()
}
