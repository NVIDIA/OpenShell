// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Proc macros for declaring per-handler gRPC auth metadata.
//!
//! `#[rpc_authz(service = "...")]` is applied to a tonic service `impl`
//! block. Each method inside the impl carries an `#[rpc_auth(...)]`
//! attribute describing its auth mode, optional Bearer scope, and
//! required role. The macro emits a const `&[MethodAuth]` adjacent to
//! the impl and re-emits the impl block with the per-method
//! `#[rpc_auth]` attributes stripped so other macros (notably
//! `#[tonic::async_trait]`) see a clean impl.
//!
//! Generated code references `crate::auth::method_authz::{MethodAuth,
//! AuthMode, Role}`, so the macro is only intended for use inside the
//! `openshell-server` crate.
//!
//! See `architecture/plans/scope-annotations.md` for the design.

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{
    Error, Ident, ImplItem, ItemImpl, LitStr, Meta, Result, Token, parse_macro_input,
    spanned::Spanned,
};

struct AuthzArgs {
    service: LitStr,
}

impl Parse for AuthzArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let key: Ident = input.parse()?;
        if key != "service" {
            return Err(Error::new(
                key.span(),
                "expected `service = \"<proto.service.name>\"`",
            ));
        }
        let _eq: Token![=] = input.parse()?;
        let service: LitStr = input.parse()?;
        Ok(Self { service })
    }
}

struct RpcAuth {
    mode: AuthMode,
    scope: Option<LitStr>,
    role: Option<RoleLit>,
}

#[derive(Clone, Copy)]
enum AuthMode {
    Unauthenticated,
    Sandbox,
    Bearer,
    Dual,
    Peer,
}

#[derive(Clone, Copy)]
enum RoleLit {
    Admin,
    User,
}

impl RpcAuth {
    fn parse(meta: &Meta) -> Result<Self> {
        let span = meta.span();
        let list = match meta {
            Meta::List(list) => list,
            _ => {
                return Err(Error::new(
                    span,
                    "expected `#[rpc_auth(auth = \"...\", scope = \"...\", role = \"...\")]`",
                ));
            }
        };

        let mut mode: Option<AuthMode> = None;
        let mut scope: Option<LitStr> = None;
        let mut role: Option<RoleLit> = None;

        list.parse_nested_meta(|m| {
            let ident = m
                .path
                .get_ident()
                .ok_or_else(|| m.error("expected `auth`, `scope`, or `role`"))?;

            if ident == "auth" {
                if mode.is_some() {
                    return Err(m.error("`auth` specified more than once"));
                }
                let value: LitStr = m.value()?.parse()?;
                mode = Some(parse_auth_mode(&value)?);
            } else if ident == "scope" {
                if scope.is_some() {
                    return Err(m.error("`scope` specified more than once"));
                }
                let value: LitStr = m.value()?.parse()?;
                scope = Some(value);
            } else if ident == "role" {
                if role.is_some() {
                    return Err(m.error("`role` specified more than once"));
                }
                let value: LitStr = m.value()?.parse()?;
                role = Some(parse_role(&value)?);
            } else {
                return Err(m.error("expected `auth`, `scope`, or `role`"));
            }
            Ok(())
        })?;

        let Some(mode) = mode else {
            return Err(Error::new(span, "`#[rpc_auth]` requires `auth = \"...\"`"));
        };

        match mode {
            AuthMode::Unauthenticated | AuthMode::Sandbox | AuthMode::Peer => {
                if let Some(ref s) = scope {
                    return Err(Error::new(
                        s.span(),
                        "`scope` is only valid for `auth = \"bearer\"` or `auth = \"dual\"`",
                    ));
                }
                if role.is_some() {
                    return Err(Error::new(
                        span,
                        "`role` is only valid for `auth = \"bearer\"` or `auth = \"dual\"`",
                    ));
                }
            }
            AuthMode::Bearer | AuthMode::Dual => {
                if scope.is_none() {
                    return Err(Error::new(
                        span,
                        "`auth = \"bearer\"` and `auth = \"dual\"` require `scope = \"...\"`",
                    ));
                }
                if role.is_none() {
                    return Err(Error::new(
                        span,
                        "`auth = \"bearer\"` and `auth = \"dual\"` require `role = \"...\"`",
                    ));
                }
            }
        }

        Ok(Self { mode, scope, role })
    }
}

fn parse_auth_mode(value: &LitStr) -> Result<AuthMode> {
    match value.value().as_str() {
        "unauthenticated" => Ok(AuthMode::Unauthenticated),
        "sandbox" => Ok(AuthMode::Sandbox),
        "bearer" => Ok(AuthMode::Bearer),
        "dual" => Ok(AuthMode::Dual),
        "peer" => Ok(AuthMode::Peer),
        other => Err(Error::new(
            value.span(),
            format!(
                "invalid auth mode `{other}`; expected one of `unauthenticated`, `sandbox`, `bearer`, `dual`, `peer`"
            ),
        )),
    }
}

fn parse_role(value: &LitStr) -> Result<RoleLit> {
    match value.value().as_str() {
        "admin" => Ok(RoleLit::Admin),
        "user" => Ok(RoleLit::User),
        other => Err(Error::new(
            value.span(),
            format!("invalid role `{other}`; expected `admin` or `user`"),
        )),
    }
}

/// Convert a Rust snake_case method identifier to the tonic PascalCase
/// gRPC method name (`list_sandboxes` → `ListSandboxes`).
fn snake_to_pascal(ident: &str) -> String {
    let mut out = String::with_capacity(ident.len());
    let mut upper_next = true;
    for c in ident.chars() {
        if c == '_' {
            upper_next = true;
            continue;
        }
        if upper_next {
            out.extend(c.to_uppercase());
            upper_next = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// Name of the per-service const emitted alongside the impl block. The
/// service module is what disambiguates between services — every impl
/// lives in its own module (`crate::grpc::AUTH_METADATA`,
/// `crate::inference::AUTH_METADATA`), so a fixed name reads more
/// naturally than `OPENSHELL_AUTH_METADATA` / `INFERENCE_AUTH_METADATA`.
const AUTH_METADATA_CONST: &str = "AUTH_METADATA";

fn trait_ident(item: &ItemImpl) -> Result<Ident> {
    let (_, path, _) = item.trait_.as_ref().ok_or_else(|| {
        Error::new(
            item.span(),
            "`#[rpc_authz]` must be applied to a trait impl (`impl Trait for Type`)",
        )
    })?;
    path.segments
        .last()
        .map(|seg| seg.ident.clone())
        .ok_or_else(|| Error::new(path.span(), "could not determine trait identifier"))
}

#[proc_macro_attribute]
pub fn rpc_authz(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AuthzArgs);
    let mut item = parse_macro_input!(item as ItemImpl);

    match expand(&args, &mut item) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn expand(args: &AuthzArgs, item: &mut ItemImpl) -> Result<proc_macro2::TokenStream> {
    // `trait_ident` is still called for its validation side effect: the
    // macro must be applied to a trait impl (`impl Trait for Type`).
    let trait_ident = trait_ident(item)?;
    let const_name = Ident::new(AUTH_METADATA_CONST, trait_ident.span());
    let service = args.service.value();

    let mut entries: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut seen_paths: Vec<String> = Vec::new();

    for impl_item in &mut item.items {
        let ImplItem::Fn(method) = impl_item else {
            continue;
        };

        let mut found: Option<Meta> = None;
        let mut kept = Vec::with_capacity(method.attrs.len());
        for attr in method.attrs.drain(..) {
            if attr.path().is_ident("rpc_auth") {
                if found.is_some() {
                    return Err(Error::new(
                        attr.span(),
                        "duplicate `#[rpc_auth]` on the same method",
                    ));
                }
                found = Some(attr.meta);
            } else {
                kept.push(attr);
            }
        }
        method.attrs = kept;

        let Some(meta) = found else {
            return Err(Error::new(
                method.sig.ident.span(),
                "method is missing `#[rpc_auth(...)]`; every RPC method must declare its auth metadata",
            ));
        };

        let auth = RpcAuth::parse(&meta)?;
        let method_path = format!(
            "/{}/{}",
            service,
            snake_to_pascal(&method.sig.ident.to_string())
        );

        if seen_paths.contains(&method_path) {
            return Err(Error::new(
                method.sig.ident.span(),
                format!("duplicate gRPC method path `{method_path}`"),
            ));
        }
        seen_paths.push(method_path.clone());

        let mode_tokens = match auth.mode {
            AuthMode::Unauthenticated => {
                quote! { crate::auth::method_authz::AuthMode::Unauthenticated }
            }
            AuthMode::Sandbox => {
                quote! { crate::auth::method_authz::AuthMode::Sandbox }
            }
            AuthMode::Bearer => quote! { crate::auth::method_authz::AuthMode::Bearer },
            AuthMode::Dual => quote! { crate::auth::method_authz::AuthMode::Dual },
            AuthMode::Peer => quote! { crate::auth::method_authz::AuthMode::Peer },
        };

        let scope_tokens = match &auth.scope {
            Some(s) => quote! { ::core::option::Option::Some(#s) },
            None => quote! { ::core::option::Option::None },
        };

        let role_tokens = match auth.role {
            Some(RoleLit::Admin) => {
                quote! { ::core::option::Option::Some(crate::auth::method_authz::Role::Admin) }
            }
            Some(RoleLit::User) => {
                quote! { ::core::option::Option::Some(crate::auth::method_authz::Role::User) }
            }
            None => quote! { ::core::option::Option::None },
        };

        entries.push(quote! {
            crate::auth::method_authz::MethodAuth {
                path: #method_path,
                mode: #mode_tokens,
                scope: #scope_tokens,
                role: #role_tokens,
            }
        });
    }

    let entries_count = entries.len();
    let entries_array = quote! { [#(#entries),*] };

    Ok(quote! {
        pub const #const_name: &[crate::auth::method_authz::MethodAuth; #entries_count] = &#entries_array;

        #item
    })
}
