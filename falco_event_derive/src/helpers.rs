use attribute_derive::{AttributeIdent, FromAttr};
use proc_macro2::Ident;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{
    GenericParam, Generics, Lifetime, LifetimeParam, PredicateLifetime, Token, WhereClause,
    WherePredicate,
};

pub fn add_raw_event_lifetimes(
    name: &Ident,
    generics: &Generics,
    where_clause: Option<&WhereClause>,
) -> (Punctuated<GenericParam, Comma>, WhereClause) {
    let mut impl_ref_generics: Punctuated<GenericParam, syn::token::Comma> =
        generics.params.iter().cloned().collect();

    let raw_event_lt = Lifetime::new("'raw_event", name.span());
    let mut ref_where_clause = where_clause.cloned().unwrap_or_else(|| WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });

    let mut outlives: Punctuated<Lifetime, syn::token::Plus> = Punctuated::new();
    for g in &impl_ref_generics {
        if let GenericParam::Lifetime(lt) = g {
            outlives.push(lt.lifetime.clone());
        }
    }

    if !outlives.is_empty() {
        ref_where_clause
            .predicates
            .push(WherePredicate::Lifetime(PredicateLifetime {
                lifetime: raw_event_lt.clone(),
                colon_token: Token![:](name.span()),
                bounds: outlives,
            }));
    }

    impl_ref_generics.insert(0, GenericParam::Lifetime(LifetimeParam::new(raw_event_lt)));
    (impl_ref_generics, ref_where_clause)
}

pub fn parse_attr<T: FromAttr + AttributeIdent>(
    attrs: &[syn::Attribute],
) -> Result<Option<T>, syn::Error> {
    if attrs.iter().any(|attr| T::is_ident(attr.meta.path())) {
        Ok(Some(T::from_attributes(attrs)?))
    } else {
        Ok(None)
    }
}

#[derive(FromAttr)]
#[from_attr(ident = falco_event_crate)]
pub struct EventCratePath(pub syn::Path);

pub fn get_crate_path(
    attrs: &[syn::Attribute],
) -> Result<proc_macro2::TokenStream, proc_macro2::TokenStream> {
    match parse_attr::<EventCratePath>(attrs) {
        Ok(Some(EventCratePath(crate_path))) => Ok(quote!(#crate_path)),
        Ok(None) => Ok(quote!(falco_event)),
        Err(e) => Err(e.to_compile_error()),
    }
}
