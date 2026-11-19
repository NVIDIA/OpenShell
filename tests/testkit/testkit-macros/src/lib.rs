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
//! The attribute generates three items:
//!
//! - a hidden `async fn` that runs the original function through
//!   `testkit::run`, with the original function nested in it;
//! - under `#[cfg(test)]`, a `#[tokio::test]` wrapper with the same name that
//!   calls it, so `cargo test` and nextest run the test like any other and the
//!   test name is the function name;
//! - an entry in `testkit`'s test registry, with the test's family, name,
//!   description, and `#[ignore]`, which `testkit::main()` runs.
//!
//! Other attributes, such as `#[ignore]` or `#[cfg(...)]`, move to the
//! wrapper. `#[cfg(...)]` also applies to the other two items, and lint
//! attributes (`allow`, `warn`, `deny`, `forbid`) also to the hidden
//! function. `#[should_panic]` is rejected: a testkit test panics on any
//! failure, so it would pass for the wrong reason. Check the expected failure
//! in the body instead. `#[cfg_attr]` and `#[expect]` are rejected too.
//!
//! A test's family is the first directory under `tests/suites/` in its
//! crate's path: `conformance` for `tests/suites/conformance`, `features` for
//! `tests/suites/features/<name>`.

use std::path::Path;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Attribute, Expr, ExprLit, ItemFn, Lit, LitStr, Meta};

#[proc_macro_attribute]
pub fn test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let family = std::env::var_os("CARGO_MANIFEST_DIR").and_then(|dir| family_of(Path::new(&dir)));
    expand(attr.into(), item.into(), family.as_deref())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand(
    attr: TokenStream2,
    item: TokenStream2,
    family: Option<&str>,
) -> syn::Result<TokenStream2> {
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
    for attr in &body.attrs {
        let message = if attr.path().is_ident("should_panic") {
            "testkit tests panic on any failure, so `#[should_panic]` would pass for the \
             wrong reason; check the expected failure in the body, for example with \
             `CliOutput::failure` and `testkit::ensure!`"
        } else if attr.path().is_ident("cfg_attr") {
            // The registration reads `#[ignore]` and `#[cfg]` directly, so it
            // would not see them inside `cfg_attr`.
            "`#[cfg_attr]` is not supported on testkit tests; use `#[cfg]` or `#[ignore]` \
             directly"
        } else if attr.path().is_ident("expect") {
            // The lint attributes are copied to two functions, and only one
            // of them would raise the lint.
            "`#[expect]` is not supported on testkit tests; use `#[allow]`"
        } else {
            continue;
        };
        return Err(syn::Error::new_spanned(attr, message));
    }
    let description = doc_comment(&body.attrs);
    if description.is_empty() {
        return Err(syn::Error::new(
            body.sig.ident.span(),
            "testkit tests need a doc comment describing the behavior they verify",
        ));
    }
    let ignore = ignore(&body.attrs)?;

    let name = body.sig.ident.clone();
    let name_str = LitStr::new(&name.to_string(), name.span());
    let description = LitStr::new(&description, name.span());
    let family = match family {
        Some(family) => quote!(::core::option::Option::Some(#family)),
        None => quote!(::core::option::Option::None),
    };
    let (ignored, ignore_reason) = match ignore {
        None => (false, quote!(::core::option::Option::None)),
        Some(None) => (true, quote!(::core::option::Option::None)),
        Some(Some(reason)) => (true, quote!(::core::option::Option::Some(#reason))),
    };

    let vis = body.vis.clone();
    let attrs = std::mem::take(&mut body.attrs);
    let cfgs: Vec<&Attribute> = attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .collect();
    // `#[cfg]` and lint attributes such as `#[allow(...)]` must reach the
    // body, which is nested in the hidden function. Anything else is for the
    // test itself, so goes on the wrapper only.
    let body_attrs: Vec<&Attribute> = attrs
        .iter()
        .filter(|attr| {
            ["cfg", "allow", "warn", "deny", "forbid"]
                .iter()
                .any(|name| attr.path().is_ident(name))
        })
        .collect();
    body.vis = syn::Visibility::Inherited;
    body.sig.ident = format_ident!("body");
    let entry = format_ident!("__testkit_{}", name);

    Ok(quote! {
        #(#body_attrs)*
        #[doc(hidden)]
        async fn #entry() {
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

        #(#attrs)*
        #[cfg(test)]
        #[::testkit::__private::tokio::test(crate = "::testkit::__private::tokio")]
        #vis async fn #name() {
            #entry().await;
        }

        #(#cfgs)*
        const _: () = {
            #[::testkit::__private::linkme::distributed_slice(::testkit::__private::TESTS)]
            #[linkme(crate = ::testkit::__private::linkme)]
            static TEST: ::testkit::Test = ::testkit::Test {
                info: ::testkit::TestInfo {
                    name: #name_str,
                    description: #description,
                },
                family: #family,
                module_path: ::core::module_path!(),
                ignored: #ignored,
                ignore_reason: #ignore_reason,
                run: || ::std::boxed::Box::pin(#entry()),
            };
        };
    })
}

/// `#[test]`, `#[tokio::test]`, or another test attribute.
fn is_test_attr(attr: &Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "test")
}

/// `None` if the test is not ignored, else the `#[ignore = "..."]` reason if
/// it has one.
fn ignore(attrs: &[Attribute]) -> syn::Result<Option<Option<LitStr>>> {
    let Some(attr) = attrs.iter().find(|attr| attr.path().is_ident("ignore")) else {
        return Ok(None);
    };
    match &attr.meta {
        Meta::Path(_) => Ok(Some(None)),
        Meta::NameValue(meta) => match &meta.value {
            Expr::Lit(ExprLit {
                lit: Lit::Str(reason),
                ..
            }) => Ok(Some(Some(reason.clone()))),
            value => Err(syn::Error::new_spanned(
                value,
                "the `#[ignore]` reason must be a string literal",
            )),
        },
        Meta::List(_) => Err(syn::Error::new_spanned(
            attr,
            "use `#[ignore]` or `#[ignore = \"reason\"]`",
        )),
    }
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

/// The family of a suite crate in `manifest_dir`: the first directory under
/// the nearest enclosing `suites/`.
fn family_of(manifest_dir: &Path) -> Option<String> {
    let components: Vec<_> = manifest_dir
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    let suites = components
        .iter()
        .rposition(|component| *component == "suites")?;
    components
        .get(suites + 1)
        .map(|family| (*family).to_string())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{expand, family_of};

    const OK_FN: &str = "async fn t(cx: &mut Context) -> testkit::Result { Ok(()) }";

    // A suite only compiles correct tests, so it never reaches these errors.
    // `testkit/tests/macro.rs` checks what correct tests expand to.
    #[test]
    fn rejects_misuse() {
        for (attr, item, error) in [
            (
                "id = \"t-1\"",
                format!("/// Doc.\n{OK_FN}"),
                "takes no arguments",
            ),
            ("", OK_FN.to_string(), "doc comment"),
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
                format!("/// Doc.\n#[tokio::test]\n{OK_FN}"),
                "already makes this a test",
            ),
            (
                "",
                format!("/// Doc.\n#[should_panic]\n{OK_FN}"),
                "`#[should_panic]`",
            ),
            (
                "",
                format!("/// Doc.\n#[ignore(later)]\n{OK_FN}"),
                "`#[ignore]` or",
            ),
            (
                "",
                format!("/// Doc.\n#[ignore = 1]\n{OK_FN}"),
                "string literal",
            ),
            (
                "",
                format!("/// Doc.\n#[cfg_attr(unix, ignore)]\n{OK_FN}"),
                "`#[cfg_attr]` is not supported",
            ),
            (
                "",
                format!("/// Doc.\n#[expect(unused)]\n{OK_FN}"),
                "`#[expect]` is not supported",
            ),
        ] {
            let err = expand(attr.parse().unwrap(), item.parse().unwrap(), None).unwrap_err();
            assert!(err.to_string().contains(error), "{item}: {err}");
        }
    }

    #[test]
    fn family_is_the_directory_under_suites() {
        for (dir, family) in [
            ("/repo/tests/suites/conformance", Some("conformance")),
            (
                "/repo/tests/suites/features/provider-refresh/keycloak",
                Some("features"),
            ),
            ("/a/suites/x/tests/suites/drivers/podman", Some("drivers")),
            ("/repo/tests/testkit/testkit", None),
            ("/repo/tests/suites", None),
        ] {
            assert_eq!(family_of(Path::new(dir)).as_deref(), family, "{dir}");
        }
    }
}
