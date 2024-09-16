#![doc = include_str!("../README.md")]
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_macro_input, DeriveInput};

fn ident_to_cstr(ident: &Ident) -> syn::LitCStr {
    let mut name = ident.to_string();
    name.push('\0');
    syn::LitCStr::new(
        std::ffi::CStr::from_bytes_with_nul(name.as_bytes()).unwrap(),
        ident.span(),
    )
}

#[proc_macro_derive(Entry, attributes(static_only, dynamic, readonly, hidden))]
pub fn derive_entry(input: TokenStream) -> TokenStream {
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
                "Only structs with named fields can derive `Entry`",
            )
            .to_compile_error(),
        );
    };

    let name = &input.ident;
    let syn::Fields::Named(fields) = data.fields else {
        return TokenStream::from(
            syn::Error::new(
                input.ident.span(),
                "Only structs with named fields can derive `Entry`",
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
        let field_name_str = ident_to_cstr(field_name);
        let ty = &f.ty;
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

#[proc_macro_derive(TableMetadata, attributes(entry_type, name, custom))]
pub fn derive_table_metadata(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let syn::Data::Struct(data) = input.data else {
        return TokenStream::from(
            syn::Error::new(
                input.ident.span(),
                "Only structs with named fields can derive `TableMetadata`",
            )
            .to_compile_error(),
        );
    };

    let name = &input.ident;
    let syn::Fields::Named(fields) = data.fields else {
        return TokenStream::from(
            syn::Error::new(
                input.ident.span(),
                "Only structs with named fields can derive `TableMetadata`",
            )
            .to_compile_error(),
        );
    };

    let fields = fields.named;

    let metadata_macro_args = fields.iter().filter_map(|f| {
        let field = f.ident.as_ref()?;
        let field_name = f
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("name"))
            .filter_map(|a| a.parse_args::<syn::LitCStr>().ok())
            .next()
            .unwrap_or_else(|| ident_to_cstr(field));

        let is_custom = f.attrs.iter().any(|f| f.path().is_ident("custom"));

        if is_custom {
            Some(quote!(add_field(#field, #field_name)))
        } else {
            Some(quote!(get_field(#field, #field_name)))
        }
    });

    let impl_table_metadata = quote!(falco_plugin::impl_import_table_metadata!(
        for #name => {
            #(#metadata_macro_args;)*
        }
    ););

    let entry_type = input
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("entry_type"))
        .filter_map(|a| a.parse_args::<Ident>().ok())
        .next();

    let mut field_traits = Vec::new();
    let mut field_trait_impls = vec![impl_table_metadata];

    let private_ns = Ident::new(&format!("__falco_plugin_private_{}", name), name.span());
    if let Some(entry_type) = entry_type {
        for f in fields {
            let Some(field_name) = f.ident.as_ref() else {
                continue;
            };
            let ty = &f.ty;

            let getter_name = Ident::new(&format!("get_{}", field_name), field_name.span());
            let table_getter_name =
                Ident::new(&format!("get_{}_by_key", field_name), field_name.span());
            let setter_name = Ident::new(&format!("set_{}", field_name), field_name.span());

            field_traits.push(quote!(
                ::falco_plugin::impl_import_table_accessor_traits!(
                    #field_name: #getter_name, #table_getter_name, #setter_name
                );
            ));
            field_trait_impls.push(quote!(
                ::falco_plugin::impl_import_table_accessor_impls!(
                    use #private_ns::#field_name;
                    #field_name(#ty) for #entry_type; meta #name =>
                        #getter_name, #table_getter_name, #setter_name
                );
            ));
        }
    }

    quote!(
        #[allow(non_snake_case)]
        mod #private_ns {
            #(#field_traits)*
        }

        #(#field_trait_impls)*

        use #private_ns::*;
    )
    .into()
}
