// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The single definition of what a `#[testkit::test]` function declares.
//!
//! The `#[testkit::test]` macro parses tests through this crate. Tools that
//! list tests without compiling them use it too, so they cannot disagree
//! with the macro about a test's ID, name, description, or requirements.

use std::hash::{BuildHasher, Hasher};

use proc_macro2::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, ExprLit, Ident, Item, ItemFn, Lit, LitStr, Meta, Token, bracketed};

/// Prefix of every test ID.
pub const ID_PREFIX: &str = "t-";
/// Number of random characters after the prefix.
const ID_LEN: usize = 8;
const ID_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// What a test declares.
#[derive(Clone, Debug)]
pub struct TestSpec {
    /// The stable test ID from `id = "..."`. It never changes, including when
    /// the test is renamed or moved to another suite or family.
    pub id: String,
    /// The function name, which is also the nextest test name.
    pub name: Ident,
    /// The doc comment, joined into one line.
    pub description: String,
    /// Capability names, as written in `requires = [...]`.
    pub requires: Vec<Ident>,
}

/// Arguments accepted by `#[testkit::test(...)]`.
#[derive(Default)]
struct Args {
    id: Option<LitStr>,
    requires: Vec<Ident>,
}

impl Parse for Args {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut args = Self::default();
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            if key == "id" {
                if args.id.is_some() {
                    return Err(syn::Error::new(key.span(), "duplicate argument `id`"));
                }
                args.id = Some(input.parse()?);
            } else if key == "requires" {
                let content;
                bracketed!(content in input);
                args.requires
                    .extend(Punctuated::<Ident, Token![,]>::parse_terminated(&content)?);
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    format!(
                        "unknown argument `{key}`; expected `id = \"...\"` or `requires = [...]`"
                    ),
                ));
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(args)
    }
}

/// Parse a test from the attribute's arguments and the function it marks.
pub fn parse(args: TokenStream, item: &ItemFn) -> syn::Result<TestSpec> {
    let args: Args = syn::parse2(args)?;

    if item.sig.asyncness.is_none() {
        return Err(syn::Error::new_spanned(
            item.sig.fn_token,
            "testkit tests must be `async fn`",
        ));
    }
    if item.sig.inputs.len() != 1 {
        return Err(syn::Error::new_spanned(
            &item.sig.inputs,
            "testkit tests take exactly one argument: `cx: &mut testkit::Context`",
        ));
    }

    let description = doc_comment(&item.attrs);
    if description.is_empty() {
        return Err(syn::Error::new(
            item.sig.ident.span(),
            "testkit tests need a doc comment describing the behavior they verify",
        ));
    }

    let Some(id) = args.id else {
        return Err(syn::Error::new(
            item.sig.ident.span(),
            format!(
                "testkit tests need a stable `id`; for a new test use `id = \"{}\"`",
                generate_id()
            ),
        ));
    };
    if !is_valid_id(&id.value()) {
        return Err(syn::Error::new(
            id.span(),
            format!(
                "test IDs are `{ID_PREFIX}` followed by {ID_LEN} lowercase letters or digits; for a new test use `id = \"{}\"`",
                generate_id()
            ),
        ));
    }

    Ok(TestSpec {
        id: id.value(),
        name: item.sig.ident.clone(),
        description,
        requires: args.requires,
    })
}

/// Whether `id` has the test ID form: the prefix and lowercase base-36 characters.
pub fn is_valid_id(id: &str) -> bool {
    id.strip_prefix(ID_PREFIX).is_some_and(|rest| {
        rest.len() == ID_LEN
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

/// A fresh random test ID, offered in the error for a missing or invalid one.
/// Uses the standard library's per-process random hash keys, so this crate
/// needs no RNG dependency.
pub fn generate_id() -> String {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos()),
    );
    let mut value = hasher.finish();
    let mut id = String::from(ID_PREFIX);
    for _ in 0..ID_LEN {
        id.push(char::from(ID_ALPHABET[(value % 36) as usize]));
        value /= 36;
    }
    id
}

/// Find every `#[testkit::test]` function in a source file.
pub fn scan(source: &str) -> syn::Result<Vec<TestSpec>> {
    let file = syn::parse_file(source)?;
    let mut tests = Vec::new();
    for item in &file.items {
        let Item::Fn(item) = item else {
            continue;
        };
        let Some(attr) = item.attrs.iter().find(|attr| is_testkit_test(attr)) else {
            continue;
        };
        let args = match &attr.meta {
            Meta::Path(_) => TokenStream::new(),
            Meta::List(list) => list.tokens.clone(),
            Meta::NameValue(meta) => {
                return Err(syn::Error::new_spanned(
                    meta,
                    "expected `#[testkit::test]` or `#[testkit::test(...)]`",
                ));
            }
        };
        tests.push(parse(args, item)?);
    }
    Ok(tests)
}

fn is_testkit_test(attr: &Attribute) -> bool {
    let segments: Vec<_> = attr.path().segments.iter().collect();
    segments.len() == 2 && segments[0].ident == "testkit" && segments[1].ident == "test"
}

/// The doc comment, joined into one line. Empty if there is none.
pub fn doc_comment(attrs: &[Attribute]) -> String {
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
    use super::*;

    fn parse_str(args: &str, item: &str) -> syn::Result<TestSpec> {
        parse(args.parse().unwrap(), &syn::parse_str(item).unwrap())
    }

    const ID: &str = "id = \"t-0123abcd\"";

    #[test]
    fn parses_id_name_description_and_requirements() {
        let spec = parse_str(
            "id = \"t-0123abcd\", requires = [service_exposure, gpu]",
            "/// First line\n/// second line.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap();
        assert_eq!(spec.id, "t-0123abcd");
        assert_eq!(spec.name, "t");
        assert_eq!(spec.description, "First line second line.");
        assert_eq!(spec.requires, ["service_exposure", "gpu"]);
    }

    #[test]
    fn rejects_missing_id_and_suggests_one() {
        let err = parse_str(
            "",
            "/// Doc.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("need a stable `id`"), "{err}");
        let suggested = err.split('"').nth(1).unwrap();
        assert!(is_valid_id(suggested), "{err}");
    }

    #[test]
    fn rejects_malformed_id() {
        for id in [
            "t-0123ABCD",
            "t-0123abc",
            "x-0123abcd",
            "0123abcd",
            "t-0123abcde",
        ] {
            let err = parse_str(
                &format!("id = \"{id}\""),
                "/// Doc.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
            )
            .unwrap_err();
            assert!(err.to_string().contains("test IDs are"), "{id}: {err}");
        }
    }

    #[test]
    fn rejects_duplicate_id_argument() {
        let err = parse_str(
            "id = \"t-0123abcd\", id = \"t-0123abce\"",
            "/// Doc.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate argument"), "{err}");
    }

    #[test]
    fn generated_ids_are_valid_and_distinct() {
        let a = generate_id();
        let b = generate_id();
        assert!(is_valid_id(&a), "{a}");
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_missing_doc_comment() {
        let err = parse_str(
            ID,
            "async fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("doc comment"), "{err}");
    }

    #[test]
    fn rejects_sync_fn() {
        let err = parse_str(
            ID,
            "/// Doc.\nfn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("async fn"), "{err}");
    }

    #[test]
    fn rejects_wrong_arity() {
        let err =
            parse_str(ID, "/// Doc.\nasync fn t() -> testkit::Result { Ok(()) }").unwrap_err();
        assert!(err.to_string().contains("exactly one argument"), "{err}");
    }

    #[test]
    fn rejects_unknown_argument() {
        let err = parse_str(
            "id = \"t-0123abcd\", timeout = [x]",
            "/// Doc.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown argument"), "{err}");
    }

    #[test]
    fn scans_only_testkit_tests() {
        let tests = scan(
            "
            use testkit::Context;

            /// Plain.
            #[testkit::test(id = \"t-00000001\")]
            async fn plain(cx: &mut Context) -> testkit::Result { Ok(()) }

            /// Needs exposure.
            #[testkit::test(id = \"t-00000002\", requires = [service_exposure])]
            async fn exposed(cx: &mut Context) -> testkit::Result { Ok(()) }

            #[test]
            fn not_a_testkit_test() {}

            async fn helper(cx: &mut Context) {}
            ",
        )
        .unwrap();
        let names: Vec<_> = tests.iter().map(|test| test.name.to_string()).collect();
        assert_eq!(names, ["plain", "exposed"]);
        assert_eq!(tests[1].id, "t-00000002");
        assert_eq!(tests[1].requires, ["service_exposure"]);
    }

    #[test]
    fn scan_reports_invalid_tests() {
        let err = scan("#[testkit::test]\nasync fn t(cx: &mut Context) {}").unwrap_err();
        assert!(err.to_string().contains("doc comment"), "{err}");
    }
}
