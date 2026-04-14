//! Default visit impls for naively visitable types.

use core::fmt;

#[cfg(feature = "alloc")]
use crate::template::context::AssocVisitor as _;
use crate::template::context::{ListVisitor as _, Visitor};

/// Make visitor visit the value that implements [`VisitValueNaive`] trait.
pub fn visit_value_naive<V, T>(visitor: V, value: T) -> V::Result
where
    V: Visitor,
    T: VisitValueNaive,
{
    value.visit_value(visitor)
}

/// A trait for types that are expected to have "naive" visit implementation.
///
/// This trait can be implemented when a type of a value has a default variable
/// type in template expansion context, and the value (or its Rust type) itself
/// knows the type in template expansion context.
pub trait VisitValueNaive {
    /// Make visitor visit the value.
    fn visit_value<V: Visitor>(&self, visitor: V) -> V::Result;
}

impl<T: ?Sized + VisitValueNaive> VisitValueNaive for &T {
    #[inline]
    fn visit_value<V: Visitor>(&self, visitor: V) -> V::Result {
        (*self).visit_value(visitor)
    }
}

impl VisitValueNaive for core::convert::Infallible {
    fn visit_value<V: Visitor>(&self, _visitor: V) -> V::Result {
        match *self {}
    }
}

impl VisitValueNaive for () {
    fn visit_value<V: Visitor>(&self, visitor: V) -> V::Result {
        visitor.visit_undefined()
    }
}

impl<T: VisitValueNaive> VisitValueNaive for Option<T> {
    #[inline]
    fn visit_value<V: Visitor>(&self, visitor: V) -> V::Result {
        match self {
            Some(v) => v.visit_value(visitor),
            None => visitor.visit_undefined(),
        }
    }
}

/// Implement [`VisitValueNaive`] trait for simple (non-composite) types.
macro_rules! impl_visit_value_naive_for_display_single {
    ($ty_val:ty, $($rest:ty),* $(,)?) => {
        impl_visit_value_naive_for_display_single!($ty_val);
        impl_visit_value_naive_for_display_single!($($rest),*);
    };
    ($ty_val:ty) => {
        impl VisitValueNaive for $ty_val {
            fn visit_value<V: Visitor>(&self, visitor: V) -> V::Result {
                visitor.visit_string(self)
            }
        }
    };
}
impl_visit_value_naive_for_display_single!(i8, i16, i32, i64, i128, isize);
impl_visit_value_naive_for_display_single!(u8, u16, u32, u64, u128, usize);
impl_visit_value_naive_for_display_single!(str);
#[cfg(feature = "alloc")]
impl_visit_value_naive_for_display_single!(
    alloc::string::String,
    alloc::boxed::Box<str>,
    alloc::borrow::Cow<'_, str>,
);

/// Implement [`VisitValueNaive`] trait for list types.
macro_rules! impl_visit_value_naive_for_display_list {
    ($ty_val:ty, $($rest:ty),* $(,)?) => {
        impl_visit_value_naive_for_display_list!($ty_val);
        impl_visit_value_naive_for_display_list!($($rest),*);
    };
    ($ty_val:ty) => {
        impl<T: fmt::Display> VisitValueNaive for $ty_val {
            fn visit_value<V: Visitor>(&self, visitor: V) -> V::Result {
                visitor.visit_list().visit_items_and_finish(self)
            }
        }
    };
}
// NOTE: By implementing list formatting for `[T]`, it becomes impossible to
// add implementation of associative array formatting for `[(K, V)]`. Since it
// would be hard to support both (think of the case when `(K, V)` itself has
// `Display` implementation), only supporting list formatting is a reasonable
// compromise... at least it's better than providing nothing for `[T]`.
impl_visit_value_naive_for_display_list!([T]);
#[cfg(feature = "alloc")]
impl_visit_value_naive_for_display_list!(alloc::vec::Vec<T>, alloc::collections::BTreeSet<T>);
#[cfg(feature = "std")]
impl_visit_value_naive_for_display_list!(std::collections::HashSet<T>);

impl<T: fmt::Display, const N: usize> VisitValueNaive for [T; N] {
    #[inline]
    fn visit_value<V: Visitor>(&self, visitor: V) -> V::Result {
        visitor.visit_list().visit_items_and_finish(self)
    }
}

/// Implement [`VisitValueNaive`] trait for associative array types.
#[cfg(feature = "alloc")]
macro_rules! impl_visit_value_naive_for_display_assoc {
    ($ty_val:ty, $($rest:ty),* $(,)?) => {
        impl_visit_value_naive_for_display_assoc!($ty_val);
        impl_visit_value_naive_for_display_assoc!($($rest),*);
    };
    ($ty_val:ty) => {
        impl<K: fmt::Display, T: fmt::Display> VisitValueNaive for $ty_val {
            fn visit_value<V: Visitor>(&self, visitor: V) -> V::Result {
                visitor.visit_assoc().visit_entries_and_finish(self)
            }
        }
    };
}
#[cfg(feature = "alloc")]
impl_visit_value_naive_for_display_assoc!(alloc::collections::BTreeMap<K, T>);
#[cfg(feature = "std")]
impl_visit_value_naive_for_display_assoc!(std::collections::HashMap<K, T>);
