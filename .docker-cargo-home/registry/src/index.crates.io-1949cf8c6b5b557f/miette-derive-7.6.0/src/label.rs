use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parenthesized,
    parse::{Parse, ParseStream},
    spanned::Spanned,
    Token,
};

use crate::{
    diagnostic::{DiagnosticConcreteArgs, DiagnosticDef},
    fmt::{self, Display},
    forward::WhichFn,
    utils::{display_pat_members, gen_all_variants_with},
};

pub struct Labels(Vec<Label>);

#[derive(PartialEq, Eq)]
enum LabelType {
    Default,
    Primary,
    Collection,
}

struct Label {
    label: Option<Display>,
    ty: syn::Type,
    span: syn::Member,
    lbl_ty: LabelType,
}

struct LabelAttr {
    label: Option<Display>,
    lbl_ty: LabelType,
}

impl Parse for LabelAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Skip a token.
        // This should receive one of:
        // - label = "..."
        // - label("...")
        let _ = input.step(|cursor| {
            if let Some((_, next)) = cursor.token_tree() {
                Ok(((), next))
            } else {
                Err(cursor.error("unexpected empty attribute"))
            }
        });
        let la = input.lookahead1();
        let (lbl_ty, label) = if la.peek(syn::token::Paren) {
            // #[label(primary?, "{}", x)]
            let content;
            parenthesized!(content in input);

            let attr = match content.parse::<Option<syn::Ident>>()? {
                Some(ident) if ident == "primary" => {
                    let _ = content.parse::<Token![,]>();
                    LabelType::Primary
                }
                Some(ident) if ident == "collection" => {
                    let _ = content.parse::<Token![,]>();
                    LabelType::Collection
                }
                Some(_) => {
                    return Err(syn::Error::new(input.span(), "Invalid argument to label() attribute. The argument must be a literal string or either the keyword `primary` or `collection`."));
                }
                _ => LabelType::Default,
            };

            if content.peek(syn::LitStr) {
                let fmt = content.parse()?;
                let args = if content.is_empty() {
                    TokenStream::new()
                } else {
                    fmt::parse_token_expr(&content, false)?
                };
                let display = Display {
                    fmt,
                    args,
                    has_bonus_display: false,
                };
                (attr, Some(display))
            } else if !content.is_empty() {
                return Err(syn::Error::new(input.span(), "Invalid argument to label() attribute. The argument must be a literal string or either the keyword `primary` or `collection`."));
            } else {
                (attr, None)
            }
        } else if la.peek(Token![=]) {
            // #[label = "blabla"]
            input.parse::<Token![=]>()?;
            (
                LabelType::Default,
                Some(Display {
                    fmt: input.parse()?,
                    args: TokenStream::new(),
                    has_bonus_display: false,
                }),
            )
        } else {
            (LabelType::Default, None)
        };
        Ok(LabelAttr { label, lbl_ty })
    }
}

impl Labels {
    pub fn from_fields(fields: &syn::Fields) -> syn::Result<Option<Self>> {
        match fields {
            syn::Fields::Named(named) => Self::from_fields_vec(named.named.iter().collect()),
            syn::Fields::Unnamed(unnamed) => {
                Self::from_fields_vec(unnamed.unnamed.iter().collect())
            }
            syn::Fields::Unit => Ok(None),
        }
    }

    fn from_fields_vec(fields: Vec<&syn::Field>) -> syn::Result<Option<Self>> {
        let mut labels = Vec::new();
        for (i, field) in fields.iter().enumerate() {
            for attr in &field.attrs {
                if attr.path().is_ident("label") {
                    let span = if let Some(ident) = field.ident.clone() {
                        syn::Member::Named(ident)
                    } else {
                        syn::Member::Unnamed(syn::Index {
                            index: i as u32,
                            span: field.span(),
                        })
                    };
                    use quote::ToTokens;
                    let LabelAttr { label, lbl_ty } =
                        syn::parse2::<LabelAttr>(attr.meta.to_token_stream())?;

                    if lbl_ty == LabelType::Primary
                        && labels
                            .iter()
                            .any(|l: &Label| l.lbl_ty == LabelType::Primary)
                    {
                        return Err(syn::Error::new(
                            field.span(),
                            "Cannot have more than one primary label.",
                        ));
                    }

                    labels.push(Label {
                        label,
                        span,
                        ty: field.ty.clone(),
                        lbl_ty,
                    });
                }
            }
        }
        if labels.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Labels(labels)))
        }
    }

    pub(crate) fn gen_struct(&self, fields: &syn::Fields) -> Option<TokenStream> {
        let (display_pat, display_members) = display_pat_members(fields);
        let labels = self.0.iter().filter_map(|highlight| {
            let Label {
                span,
                label,
                ty,
                lbl_ty,
            } = highlight;
            if *lbl_ty == LabelType::Collection {
                return None;
            }
            let var = quote! { __miette_internal_var };
            let display = if let Some(display) = label {
                let (fmt, args) = display.expand_shorthand_cloned(&display_members);
                quote! { std::option::Option::Some(format!(#fmt #args)) }
            } else {
                quote! { std::option::Option::None }
            };
            let ctor = if *lbl_ty == LabelType::Primary {
                quote! { miette::LabeledSpan::new_primary_with_span }
            } else {
                quote! { miette::LabeledSpan::new_with_span }
            };

            Some(quote! {
                miette::macro_helpers::OptionalWrapper::<#ty>::new().to_option(&self.#span)
                .map(|#var| #ctor(
                    #display,
                    #var.clone(),
                ))
            })
        });
        let collections_chain = self.0.iter().filter_map(|label| {
            let Label {
                span,
                label,
                ty: _,
                lbl_ty,
            } = label;
            if *lbl_ty != LabelType::Collection {
                return None;
            }
            let display = if let Some(display) = label {
                let (fmt, args) = display.expand_shorthand_cloned(&display_members);
                quote! { std::option::Option::Some(format!(#fmt #args)) }
            } else {
                quote! { std::option::Option::None }
            };
            Some(quote! {
                .chain({
                    let display = #display;
                    self.#span.iter().map(move |span| {
                        use miette::macro_helpers::{ToLabelSpanWrapper,ToLabeledSpan};
                        let mut labeled_span = ToLabelSpanWrapper::to_labeled_span(span.clone());
                        if display.is_some() && labeled_span.label().is_none() {
                            labeled_span.set_label(display.clone())
                        }
                        Some(labeled_span)
                    })
                })
            })
        });

        Some(quote! {
            #[allow(unused_variables)]
            fn labels(&self) -> std::option::Option<std::boxed::Box<dyn std::iter::Iterator<Item = miette::LabeledSpan> + '_>> {
                use miette::macro_helpers::ToOption;
                let Self #display_pat = self;

                let labels_iter = vec![
                    #(#labels),*
                ]
                .into_iter()
                #(#collections_chain)*;

                std::option::Option::Some(Box::new(labels_iter.filter(Option::is_some).map(Option::unwrap)))
            }
        })
    }

    pub(crate) fn gen_enum(variants: &[DiagnosticDef]) -> Option<TokenStream> {
        gen_all_variants_with(
            variants,
            WhichFn::Labels,
            |ident, fields, DiagnosticConcreteArgs { labels, .. }| {
                let (display_pat, display_members) = display_pat_members(fields);
                labels.as_ref().and_then(|labels| {
                    let variant_labels = labels.0.iter().filter_map(|label| {
                        let Label { span, label, ty, lbl_ty } = label;
                        if *lbl_ty == LabelType::Collection {
                            return None;
                        }
                        let field = match &span {
                            syn::Member::Named(ident) => ident.clone(),
                            syn::Member::Unnamed(syn::Index { index, .. }) => {
                                format_ident!("_{}", index)
                            }
                        };
                        let var = quote! { __miette_internal_var };
                        let display = if let Some(display) = label {
                            let (fmt, args) = display.expand_shorthand_cloned(&display_members);
                            quote! { std::option::Option::Some(format!(#fmt #args)) }
                        } else {
                            quote! { std::option::Option::None }
                        };
                        let ctor = if *lbl_ty == LabelType::Primary {
                            quote! { miette::LabeledSpan::new_primary_with_span }
                        } else {
                            quote! { miette::LabeledSpan::new_with_span }
                        };

                        Some(quote! {
                            miette::macro_helpers::OptionalWrapper::<#ty>::new().to_option(#field)
                            .map(|#var| #ctor(
                                #display,
                                #var.clone(),
                            ))
                        })
                    });
                    let collections_chain = labels.0.iter().filter_map(|label| {
                        let Label { span, label, ty: _, lbl_ty } = label;
                        if *lbl_ty != LabelType::Collection {
                            return None;
                        }
                        let field = match &span {
                            syn::Member::Named(ident) => ident.clone(),
                            syn::Member::Unnamed(syn::Index { index, .. }) => {
                                format_ident!("_{}", index)
                            }
                        };
                        let display = if let Some(display) = label {
                            let (fmt, args) = display.expand_shorthand_cloned(&display_members);
                            quote! { std::option::Option::Some(format!(#fmt #args)) }
                        } else {
                            quote! { std::option::Option::None }
                        };
                        Some(quote! {
                            .chain({
                                let display = #display;
                                #field.iter().map(move |span| {
                                    use miette::macro_helpers::{ToLabelSpanWrapper,ToLabeledSpan};
                                    let mut labeled_span = ToLabelSpanWrapper::to_labeled_span(span.clone());
                                    if display.is_some() && labeled_span.label().is_none() {
                                        labeled_span.set_label(display.clone());
                                    }
                                    Some(labeled_span)
                                })
                            })
                        })
                    });
                    let variant_name = ident.clone();
                    match &fields {
                        syn::Fields::Unit => None,
                        _ => Some(quote! {
                            Self::#variant_name #display_pat => {
                                use miette::macro_helpers::ToOption;
                                let labels_iter = vec![
                                    #(#variant_labels),*
                                ]
                                .into_iter()
                                #(#collections_chain)*;
                                std::option::Option::Some(std::boxed::Box::new(labels_iter.filter(Option::is_some).map(Option::unwrap)))
                            }
                        }),
                    }
                })
            },
        )
    }
}
