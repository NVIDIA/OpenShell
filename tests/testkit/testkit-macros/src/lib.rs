// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `#[testkit::test]` attribute.
//!
//! A test is an `async fn` taking `&mut testkit::Context` and returning
//! `testkit::Result`. Its doc comment is the test's description and is
//! required:
//!
//! ```ignore
//! /// An exposed loopback HTTP service is reachable and goes away after delete.
//! #[testkit::test]
//! async fn expose_service(cx: &mut Context) -> testkit::Result { /* ... */ }
//! ```
//!
//! The attribute expands to a `#[tokio::test]` wrapper with the same name, so
//! the nextest test name is the function name. The original function is nested
//! in the wrapper and passed to `testkit::run`.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Attribute, Expr, ExprLit, ItemFn, Lit, LitStr, Meta};

#[proc_macro_attribute]
pub fn test(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand(attr: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    let mut body: ItemFn = syn::parse2(item)?;
    if !attr.is_empty() {
        return Err(syn::Error::new_spanned(
            attr,
            "`#[testkit::test]` takes no arguments",
        ));
    }
    if body.sig.asyncness.is_none() {
        return Err(syn::Error::new_spanned(
            body.sig.fn_token,
            "testkit tests must be `async fn`",
        ));
    }
    if body.sig.inputs.len() != 1 {
        return Err(syn::Error::new_spanned(
            &body.sig.inputs,
            "testkit tests take exactly one argument: `cx: &mut testkit::Context`",
        ));
    }
    let description = doc_comment(&body.attrs);
    if description.is_empty() {
        return Err(syn::Error::new(
            body.sig.ident.span(),
            "testkit tests need a doc comment describing the behavior they verify",
        ));
    }

    let name = body.sig.ident.clone();
    let name_str = LitStr::new(&name.to_string(), name.span());
    let description = LitStr::new(&description, name.span());

    let vis = body.vis.clone();
    let doc_attrs: Vec<_> = body
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .cloned()
        .collect();
    body.attrs.retain(|attr| !attr.path().is_ident("doc"));
    body.vis = syn::Visibility::Inherited;
    body.sig.ident = format_ident!("body");

    Ok(quote! {
        #(#doc_attrs)*
        #[::testkit::__private::tokio::test(crate = "::testkit::__private::tokio")]
        #vis async fn #name() {
            #body
            ::testkit::run(
                ::testkit::TestInfo {
                    name: #name_str,
                    description: #description,
                },
                body,
            )
            .await;
        }
    })
}

/// The doc comment, joined into one line. Empty if there is none.
fn doc_comment(attrs: &[Attribute]) -> String {
    attrs
        .iter()
        .filter_map(|attr| match &attr.meta {
            Meta::NameValue(meta) if meta.path.is_ident("doc") => match &meta.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(line),
                    ..
                }) => Some(line.value().trim().to_string()),
                _ => None,
            },
            _ => None,
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::expand;

    fn expand_str(attr: &str, item: &str) -> syn::Result<String> {
        expand(attr.parse().unwrap(), item.parse().unwrap()).map(|tokens| tokens.to_string())
    }

    #[test]
    fn expands_to_wrapper_with_same_name() {
        let out = expand_str(
            "",
            "/// First line\n/// second line.\nasync fn does_a_thing(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap();
        assert!(out.contains("async fn does_a_thing ()"), "{out}");
        assert!(out.contains("async fn body (cx : & mut Context)"), "{out}");
        assert!(out.contains("name : \"does_a_thing\""), "{out}");
        assert!(
            out.contains("description : \"First line second line.\""),
            "{out}"
        );
    }

    #[test]
    fn rejects_missing_doc_comment() {
        let err = expand_str(
            "",
            "async fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("doc comment"), "{err}");
    }

    #[test]
    fn rejects_sync_fn() {
        let err = expand_str(
            "",
            "/// Doc.\nfn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("async fn"), "{err}");
    }

    #[test]
    fn rejects_wrong_arity() {
        let err =
            expand_str("", "/// Doc.\nasync fn t() -> testkit::Result { Ok(()) }").unwrap_err();
        assert!(err.to_string().contains("exactly one argument"), "{err}");
    }

    #[test]
    fn rejects_arguments() {
        let err = expand_str(
            "id = \"t-0123abcd\"",
            "/// Doc.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("takes no arguments"), "{err}");
    }
}
