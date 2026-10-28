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
//! in the wrapper and passed to `testkit::run`. Other attributes, such as
//! `#[ignore]` or `#[cfg(...)]`, move to the wrapper. `#[should_panic]` is
//! rejected: a testkit test panics on any failure, so it would pass for the
//! wrong reason. Check the expected failure in the body instead.

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
    if let Some(attr) = body.attrs.iter().find(|attr| is_test_attr(attr)) {
        return Err(syn::Error::new_spanned(
            attr,
            "`#[testkit::test]` already makes this a test; remove this attribute",
        ));
    }
    if let Some(attr) = body
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("should_panic"))
    {
        return Err(syn::Error::new_spanned(
            attr,
            "testkit tests panic on any failure, so `#[should_panic]` would pass for the \
             wrong reason; check the expected failure in the body, for example with \
             `CliOutput::failure` and `testkit::ensure!`",
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
    let attrs = std::mem::take(&mut body.attrs);
    body.vis = syn::Visibility::Inherited;
    body.sig.ident = format_ident!("body");

    Ok(quote! {
        #(#attrs)*
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

/// `#[test]`, `#[tokio::test]`, or another test attribute.
fn is_test_attr(attr: &Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "test")
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

    // A suite only compiles correct tests, so it never reaches these errors.
    #[test]
    fn rejects_misuse() {
        let ok_fn = "async fn t(cx: &mut Context) -> testkit::Result { Ok(()) }";
        for (attr, item, error) in [
            (
                "id = \"t-1\"",
                format!("/// Doc.\n{ok_fn}"),
                "takes no arguments",
            ),
            ("", ok_fn.to_string(), "doc comment"),
            (
                "",
                "/// Doc.\nfn t(cx: &mut Context) -> testkit::Result { Ok(()) }".to_string(),
                "async fn",
            ),
            (
                "",
                "/// Doc.\nasync fn t() -> testkit::Result { Ok(()) }".to_string(),
                "exactly one argument",
            ),
            (
                "",
                format!("/// Doc.\n#[tokio::test]\n{ok_fn}"),
                "already makes this a test",
            ),
            (
                "",
                format!("/// Doc.\n#[should_panic]\n{ok_fn}"),
                "`#[should_panic]`",
            ),
        ] {
            let err = expand(attr.parse().unwrap(), item.parse().unwrap()).unwrap_err();
            assert!(err.to_string().contains(error), "{item}: {err}");
        }
    }
}
