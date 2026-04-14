//! This crate provides attribute macros for specifying API stability of public
//! API items of a crate.
//!
//! The Rust standard library has a concept of [API
//! stability](https://rustc-dev-guide.rust-lang.org/stability.html) and custom
//! attributes for managing that on a per-item basis, but most of these
//! attributes are not available for normal crates to use, with the exception of
//! the
//! [`#[deprecated]`](https://doc.rust-lang.org/reference/attributes/diagnostics.html#the-deprecated-attribute)
//! attribute. This crate seeks to provide similar attributes on stable Rust,
//! though tuned more toward what the needs of normal crate authors.
//!
//! For complete examples of how to use this crate, check out the source code
//! for the [`stability-example`
//! crate](https://github.com/sagebind/stability/tree/master/example) included
//! in the stability repository.
//!
//! Currently, only the [`#[unstable]`][macro@unstable] attribute is available.
//! Please see the documentation of that macro for an explanation on what it
//! does and how to use it.

use proc_macro::TokenStream;
use syn::{parse_macro_input, Item};

mod unstable;

/// Mark an API as unstable.
///
/// You can apply this attribute to an item in your public API that you would
/// like to expose to users, but are not yet ready for general use. This is
/// useful when you want to let users try out some new functionality for an API
/// you haven't finished testing or designing, or for whatever reason do not
/// want to commit any stability guarantees for.
///
/// This attribute does the following things to annotated items:
///
/// - Changes the visibility of the item from `pub` to `pub(crate)`, unless a
///   certain crate feature is enabled. This ensures that internal code within
///   the crate can always use the item, but downstream consumers cannot access
///   it unless they opt-in to the unstable API.
///   - Visibility of certain child items of the annotated item will also be
///     changed to match the new item visibility, such as struct fields. Children
///     that are not public will not be affected.
///   - Child items of annotated modules will *not* have their visibility changed,
///     as it might be desirable to be able to re-export them even if the module
///     visibility is restricted. You should apply the attribute to each item
///     within the module with the same feature name if you want to restrict the
///     module's contents itself and not just the module namespace.
/// - Appends an "Availability" section to the item's documentation that notes
///   that the item is unstable, and indicates the name of the crate feature to
///   enable it.
///
/// Note that unlike the `#[unstable]` attribute used [in the standard
/// library](https://rustc-dev-guide.rust-lang.org/stability.html), this
/// attribute does not apply itself recursively to child items.
///
/// Applying this attribute to non-`pub` items is pointless and does nothing.
///
/// # Arguments
///
/// The `unstable` attribute supports optional arguments that can be passed to
/// control its behavior.
///
/// - `feature`: Specify the name of the unstable feature that should control
///   this item's availability. The crate feature will have the string
///   `unstable-` prepended to it. If not specified, it will be guarded by a
///   catch-all `unstable` feature.
/// - `issue`: Provide a link or reference to a tracking issue for the unstable
///   feature. This will be included in the item's documentation.
///
/// # Examples
///
/// We can apply the attribute to a public function like so:
///
/// ```
/// /// This function does something really risky!
/// ///
/// /// Don't use it yet!
/// #[stability::unstable(feature = "risky-function")]
/// pub fn risky_function() {
///     unimplemented!()
/// }
/// ```
///
/// This will essentially be expanded to the following:
///
/// ```
/// /// This function does something really risky!
/// ///
/// /// Don't use it yet!
/// ///
/// /// # Availability
/// ///
/// /// **This API is marked as unstable** and is only available when the
/// /// `unstable-risky-function` crate feature is enabled. This comes with no
/// /// stability guarantees, and could be changed or removed at any time.
/// #[cfg(feature = "unstable-risky-function")]
/// pub fn risky_function() {
///     unimplemented!()
/// }
///
/// /// This function does something really risky!
/// ///
/// /// Don't use it yet!
/// #[cfg(not(feature = "unstable-risky-function"))]
/// pub(crate) fn risky_function() {
///     unimplemented!()
/// }
/// ```
#[proc_macro_attribute]
pub fn unstable(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut attributes = unstable::UnstableAttribute::default();
    let attributes_parser = syn::meta::parser(|meta| attributes.parse(meta));
    parse_macro_input!(args with attributes_parser);

    match parse_macro_input!(input as Item) {
        Item::Type(item_type) => attributes.expand(item_type),
        Item::Enum(item_enum) => attributes.expand(item_enum),
        Item::Struct(item_struct) => attributes.expand(item_struct),
        Item::Fn(item_fn) => attributes.expand(item_fn),
        Item::Mod(item_mod) => attributes.expand(item_mod),
        Item::Trait(item_trait) => attributes.expand(item_trait),
        Item::Const(item_const) => attributes.expand(item_const),
        Item::Static(item_static) => attributes.expand(item_static),
        Item::Use(item_use) => attributes.expand(item_use),
        _ => panic!("unsupported item type"),
    }
}
