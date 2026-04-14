//! A YAML mapping and its iterator types.

use crate::{private, Value};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    cmp::Ordering,
    collections::hash_map::DefaultHasher,
    fmt::{self, Display},
    hash::{Hash, Hasher},
    mem,
};

/// A YAML mapping in which the keys and values are both `serde_yml::Value`.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Mapping {
    /// The underlying map.
    pub map: IndexMap<Value, Value>,
}

impl Mapping {
    /// Creates an empty YAML mapping.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty YAML mapping with the given initial capacity.
    ///
    /// The mapping will be able to hold at least `capacity` elements without
    /// reallocating. If `capacity` is 0, the mapping will not allocate.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Mapping {
            map: IndexMap::with_capacity(capacity),
        }
    }

    /// Reserves capacity for at least `additional` more elements to be inserted
    /// into the mapping. The mapping may reserve more space to avoid frequent
    /// reallocations.
    ///
    /// # Panics
    ///
    /// Panics if the new allocation size overflows `usize`.
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.map.reserve(additional);
    }

    /// Shrinks the capacity of the mapping as much as possible.
    ///
    /// It will drop down as much as possible while maintaining the internal rules
    /// and possibly leaving some space in accordance with the resize policy.
    #[inline]
    pub fn shrink_to_fit(&mut self) {
        self.map.shrink_to_fit();
    }

    /// Inserts a key-value pair into the mapping.
    ///
    /// If the mapping did not have this key present, `None` is returned.
    ///
    /// If the mapping did have this key present, the value is updated, and the old
    /// value is returned.
    #[inline]
    pub fn insert(&mut self, k: Value, v: Value) -> Option<Value> {
        self.map.insert(k, v)
    }

    /// Returns `true` if the mapping contains a value for the specified key.
    ///
    /// The key may be any borrowed form of the mapping's key type, but the ordering
    /// on the borrowed form *must* match the key type's ordering.
    #[inline]
    pub fn contains_key<I: Index>(&self, index: I) -> bool {
        index.is_key_into(self)
    }

    /// Returns a reference to the value corresponding to the key.
    ///
    /// The key may be any borrowed form of the mapping's key type, but the ordering
    /// on the borrowed form *must* match the key type's ordering.
    #[inline]
    pub fn get<I: Index>(&self, index: I) -> Option<&Value> {
        index.index_into(self)
    }

    /// Returns a mutable reference to the value corresponding to the key.
    ///
    /// The key may be any borrowed form of the mapping's key type, but the ordering
    /// on the borrowed form *must* match the key type's ordering.
    #[inline]
    pub fn get_mut<I: Index>(
        &mut self,
        index: I,
    ) -> Option<&mut Value> {
        index.index_into_mut(self)
    }

    /// Gets the given key's corresponding entry in the mapping for in-place manipulation.
    #[inline]
    pub fn entry(&mut self, k: Value) -> Entry<'_> {
        match self.map.entry(k) {
            indexmap::map::Entry::Occupied(occupied) => {
                Entry::Occupied(OccupiedEntry { occupied })
            }
            indexmap::map::Entry::Vacant(vacant) => {
                Entry::Vacant(VacantEntry { vacant })
            }
        }
    }

    /// Removes a key from the mapping, returning the value at the key if the key
    /// was previously in the mapping.
    ///
    /// The key may be any borrowed form of the mapping's key type, but the ordering
    /// on the borrowed form *must* match the key type's ordering.
    ///
    /// This is equivalent to calling `swap_remove` and ignores the order of the
    /// elements.
    #[inline]
    pub fn remove<I: Index>(&mut self, index: I) -> Option<Value> {
        self.swap_remove(index)
    }

    /// Removes a key from the mapping, returning the stored key and value if the
    /// key was previously in the mapping.
    ///
    /// The key may be any borrowed form of the mapping's key type, but the ordering
    /// on the borrowed form *must* match the key type's ordering.
    ///
    /// This is equivalent to calling `swap_remove_entry` and ignores the order of the
    /// elements.
    #[inline]
    pub fn remove_entry<I: Index>(
        &mut self,
        index: I,
    ) -> Option<(Value, Value)> {
        self.swap_remove_entry(index)
    }

    /// Removes a key from the mapping, returning the value at the key if the key
    /// was previously in the mapping.
    ///
    /// The key may be any borrowed form of the mapping's key type, but the ordering
    /// on the borrowed form *must* match the key type's ordering.
    ///
    /// The element is removed by swapping it with the last element of the mapping
    /// and popping it off. This perturbs the position of the last element.
    #[inline]
    pub fn swap_remove<I: Index>(&mut self, index: I) -> Option<Value> {
        index.swap_remove_from(self)
    }

    /// Removes a key from the mapping, returning the stored key and value if the
    /// key was previously in the mapping.
    ///
    /// The key may be any borrowed form of the mapping's key type, but the ordering
    /// on the borrowed form *must* match the key type's ordering.
    ///
    /// The element is removed by swapping it with the last element of the mapping
    /// and popping it off. This perturbs the position of the last element.
    #[inline]
    pub fn swap_remove_entry<I: Index>(
        &mut self,
        index: I,
    ) -> Option<(Value, Value)> {
        index.swap_remove_entry_from(self)
    }

    /// Removes a key from the mapping, returning the value at the key if the key
    /// was previously in the mapping.
    ///
    /// The key may be any borrowed form of the mapping's key type, but the ordering
    /// on the borrowed form *must* match the key type's ordering.
    ///
    /// The element is removed by shifting all of the elements that follow it,
    /// preserving their relative order. This perturbs the index of all of those
    /// elements.
    #[inline]
    pub fn shift_remove<I: Index>(
        &mut self,
        index: I,
    ) -> Option<Value> {
        index.shift_remove_from(self)
    }

    /// Removes a key from the mapping, returning the stored key and value if the
    /// key was previously in the mapping.
    ///
    /// The key may be any borrowed form of the mapping's key type, but the ordering
    /// on the borrowed form *must* match the key type's ordering.
    ///
    /// The element is removed by shifting all of the elements that follow it,
    /// preserving their relative order. This perturbs the index of all of those
    /// elements.
    #[inline]
    pub fn shift_remove_entry<I: Index>(
        &mut self,
        index: I,
    ) -> Option<(Value, Value)> {
        index.shift_remove_entry_from(self)
    }

    /// Retains only the elements specified by the predicate.
    ///
    /// In other words, remove all pairs `(k, v)` such that `f(&k, &mut v)` returns `false`.
    #[inline]
    pub fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&Value, &mut Value) -> bool,
    {
        self.map.retain(keep);
    }

    /// Returns the number of elements the mapping can hold without reallocating.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    /// Returns the number of elements in the mapping.
    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the mapping contains no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Clears the mapping, removing all key-value pairs.
    #[inline]
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Returns an iterator over the key-value pairs of the mapping, in their order.
    ///
    /// The iterator element type is `(&'a Value, &'a Value)`.
    #[inline]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            iter: self.map.iter(),
        }
    }

    /// Returns a mutable iterator over the key-value pairs of the mapping, in their order.
    ///
    /// The iterator element type is `(&'a Value, &'a mut Value)`.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut {
            iter: self.map.iter_mut(),
        }
    }

    /// Returns an iterator over the keys of the mapping, in their order.
    ///
    /// The iterator element type is `&'a Value`.
    pub fn keys(&self) -> Keys<'_> {
        Keys {
            iter: self.map.keys(),
        }
    }

    /// Returns an owning iterator over the keys of the mapping, in their order.
    ///
    /// The iterator element type is `Value`.
    pub fn into_keys(self) -> IntoKeys {
        IntoKeys {
            iter: self.map.into_keys(),
        }
    }

    /// Returns an iterator over the values of the mapping, in their order.
    ///
    /// The iterator element type is `&'a Value`.
    pub fn values(&self) -> Values<'_> {
        Values {
            iter: self.map.values(),
        }
    }

    /// Returns a mutable iterator over the values of the mapping, in their order.
    ///
    /// The iterator element type is `&'a mut Value`.
    pub fn values_mut(&mut self) -> ValuesMut<'_> {
        ValuesMut {
            iter: self.map.values_mut(),
        }
    }

    /// Returns an owning iterator over the values of the mapping, in their order.
    ///
    /// The iterator element type is `Value`.
    pub fn into_values(self) -> IntoValues {
        IntoValues {
            iter: self.map.into_values(),
        }
    }
}

/// A trait for types that can be used to index into a `serde_yml::Mapping`.
///
/// The `get`, `get_mut`, `contains_key`, `remove`, `remove_entry`, `shift_remove`
/// and `shift_remove_entry` methods of `Mapping` use this trait to provide a uniform
/// interface for indexing with different key types.
///
/// This trait is sealed and cannot be implemented for types outside of `serde_yml`.
pub trait Index: private::Sealed {
    /// Returns `true` if the given key is present in the mapping.
    #[doc(hidden)]
    fn is_key_into(&self, v: &Mapping) -> bool;

    /// Returns a reference to the value corresponding to the key in the mapping.
    #[doc(hidden)]
    fn index_into<'a>(&self, v: &'a Mapping) -> Option<&'a Value>;

    /// Returns a mutable reference to the value corresponding to the key in the mapping.
    #[doc(hidden)]
    fn index_into_mut<'a>(
        &self,
        v: &'a mut Mapping,
    ) -> Option<&'a mut Value>;

    /// Removes the key-value pair corresponding to the key from the mapping and returns the value.
    ///
    /// The element is removed by swapping it with the last element of the mapping
    /// and popping it off. This perturbs the position of the last element.
    #[doc(hidden)]
    fn swap_remove_from(&self, v: &mut Mapping) -> Option<Value>;

    /// Removes the key-value pair corresponding to the key from the mapping and returns the key and value.
    ///
    /// The element is removed by swapping it with the last element of the mapping
    /// and popping it off. This perturbs the position of the last element.
    #[doc(hidden)]
    fn swap_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)>;

    /// Removes the key-value pair corresponding to the key from the mapping and returns the value.
    ///
    /// The element is removed by shifting all of the elements that follow it,
    /// preserving their relative order. This perturbs the index of all of those
    /// elements.
    #[doc(hidden)]
    fn shift_remove_from(&self, v: &mut Mapping) -> Option<Value>;

    /// Removes the key-value pair corresponding to the key from the mapping and returns the key and value.
    ///
    /// The element is removed by shifting all of the elements that follow it,
    /// preserving their relative order. This perturbs the index of all of those
    /// elements.
    #[doc(hidden)]
    fn shift_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)>;
}

/// A newtype wrapper for `&str` that implements `indexmap::Equivalent<Value>`
/// to allow indexing into a `Mapping` with string slices.
struct HashLikeValue<'a>(&'a str);

impl indexmap::Equivalent<Value> for HashLikeValue<'_> {
    fn equivalent(&self, key: &Value) -> bool {
        match key {
            Value::String(string) => self.0 == string,
            _ => false,
        }
    }
}

// NOTE: This impl must be consistent with Value's Hash impl.
impl Hash for HashLikeValue<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        const STRING: Value = Value::String(String::new());
        mem::discriminant(&STRING).hash(state);
        self.0.hash(state);
    }
}

/// Implements the `Index` trait for `Value`, allowing any `Value` to be used
/// as a key for indexing into a `Mapping`.
impl Index for Value {
    fn is_key_into(&self, v: &Mapping) -> bool {
        v.map.contains_key(self)
    }

    fn index_into<'a>(&self, v: &'a Mapping) -> Option<&'a Value> {
        v.map.get(self)
    }

    fn index_into_mut<'a>(
        &self,
        v: &'a mut Mapping,
    ) -> Option<&'a mut Value> {
        v.map.get_mut(self)
    }

    fn swap_remove_from(&self, v: &mut Mapping) -> Option<Value> {
        v.map.swap_remove(self)
    }

    fn swap_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)> {
        v.map.swap_remove_entry(self)
    }

    fn shift_remove_from(&self, v: &mut Mapping) -> Option<Value> {
        v.map.shift_remove(self)
    }

    fn shift_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)> {
        v.map.shift_remove_entry(self)
    }
}

/// Implements the `Index` trait for `&str`, allowing string slices to be used
/// as keys for indexing into a `Mapping`.
impl Index for str {
    fn is_key_into(&self, v: &Mapping) -> bool {
        v.map.contains_key(&HashLikeValue(self))
    }
    fn index_into<'a>(&self, v: &'a Mapping) -> Option<&'a Value> {
        v.map.get(&HashLikeValue(self))
    }
    fn index_into_mut<'a>(
        &self,
        v: &'a mut Mapping,
    ) -> Option<&'a mut Value> {
        v.map.get_mut(&HashLikeValue(self))
    }
    fn swap_remove_from(&self, v: &mut Mapping) -> Option<Value> {
        v.map.swap_remove(&HashLikeValue(self))
    }
    fn swap_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)> {
        v.map.swap_remove_entry(&HashLikeValue(self))
    }
    fn shift_remove_from(&self, v: &mut Mapping) -> Option<Value> {
        v.map.shift_remove(&HashLikeValue(self))
    }
    fn shift_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)> {
        v.map.shift_remove_entry(&HashLikeValue(self))
    }
}

/// Implements the `Index` trait for `String`, allowing owned strings to be used as keys for indexing into a `Mapping`.
impl Index for String {
    fn is_key_into(&self, v: &Mapping) -> bool {
        self.as_str().is_key_into(v)
    }
    fn index_into<'a>(&self, v: &'a Mapping) -> Option<&'a Value> {
        self.as_str().index_into(v)
    }
    fn index_into_mut<'a>(
        &self,
        v: &'a mut Mapping,
    ) -> Option<&'a mut Value> {
        self.as_str().index_into_mut(v)
    }
    fn swap_remove_from(&self, v: &mut Mapping) -> Option<Value> {
        self.as_str().swap_remove_from(v)
    }
    fn swap_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)> {
        self.as_str().swap_remove_entry_from(v)
    }
    fn shift_remove_from(&self, v: &mut Mapping) -> Option<Value> {
        self.as_str().shift_remove_from(v)
    }
    fn shift_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)> {
        self.as_str().shift_remove_entry_from(v)
    }
}

/// Implements the `Index` trait for `&String`, allowing string references to be used as keys for indexing into a `Mapping`.
impl<T> Index for &T
where
    T: ?Sized + Index,
{
    fn is_key_into(&self, v: &Mapping) -> bool {
        (**self).is_key_into(v)
    }
    fn index_into<'a>(&self, v: &'a Mapping) -> Option<&'a Value> {
        (**self).index_into(v)
    }
    fn index_into_mut<'a>(
        &self,
        v: &'a mut Mapping,
    ) -> Option<&'a mut Value> {
        (**self).index_into_mut(v)
    }
    fn swap_remove_from(&self, v: &mut Mapping) -> Option<Value> {
        (**self).swap_remove_from(v)
    }
    fn swap_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)> {
        (**self).swap_remove_entry_from(v)
    }
    fn shift_remove_from(&self, v: &mut Mapping) -> Option<Value> {
        (**self).shift_remove_from(v)
    }
    fn shift_remove_entry_from(
        &self,
        v: &mut Mapping,
    ) -> Option<(Value, Value)> {
        (**self).shift_remove_entry_from(v)
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
/// `Mapping` is hashable if its keys and values are hashable.
impl Hash for Mapping {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the kv pairs in a way that is not sensitive to their order.
        let mut xor = 0;
        for (k, v) in self {
            let mut hasher = DefaultHasher::new();
            k.hash(&mut hasher);
            v.hash(&mut hasher);
            xor ^= hasher.finish();
        }
        xor.hash(state);
    }
}

/// `Mapping` is ordered if its keys and values are ordered.
impl PartialOrd for Mapping {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let mut self_entries = Vec::from_iter(self);
        let mut other_entries = Vec::from_iter(other);

        // Sort in an arbitrary order that is consistent with Value's PartialOrd
        // impl.
        fn total_cmp(a: &Value, b: &Value) -> Ordering {
            match (a, b) {
                (Value::Null, Value::Null) => Ordering::Equal,
                (Value::Null, _) => Ordering::Less,
                (_, Value::Null) => Ordering::Greater,

                (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
                (Value::Bool(_), _) => Ordering::Less,
                (_, Value::Bool(_)) => Ordering::Greater,

                (Value::Number(a), Value::Number(b)) => a.total_cmp(b),
                (Value::Number(_), _) => Ordering::Less,
                (_, Value::Number(_)) => Ordering::Greater,

                (Value::String(a), Value::String(b)) => a.cmp(b),
                (Value::String(_), _) => Ordering::Less,
                (_, Value::String(_)) => Ordering::Greater,

                (Value::Sequence(a), Value::Sequence(b)) => {
                    iter_cmp_by(a, b, total_cmp)
                }
                (Value::Sequence(_), _) => Ordering::Less,
                (_, Value::Sequence(_)) => Ordering::Greater,

                (Value::Mapping(a), Value::Mapping(b)) => {
                    iter_cmp_by(a, b, |(ak, av), (bk, bv)| {
                        total_cmp(ak, bk)
                            .then_with(|| total_cmp(av, bv))
                    })
                }
                (Value::Mapping(_), _) => Ordering::Less,
                (_, Value::Mapping(_)) => Ordering::Greater,

                (Value::Tagged(a), Value::Tagged(b)) => a
                    .tag
                    .cmp(&b.tag)
                    .then_with(|| total_cmp(&a.value, &b.value)),
            }
        }

        fn iter_cmp_by<I, F>(this: I, other: I, mut cmp: F) -> Ordering
        where
            I: IntoIterator,
            F: FnMut(I::Item, I::Item) -> Ordering,
        {
            let mut this = this.into_iter();
            let mut other = other.into_iter();

            loop {
                let x = match this.next() {
                    None => {
                        if other.next().is_none() {
                            return Ordering::Equal;
                        } else {
                            return Ordering::Less;
                        }
                    }
                    Some(val) => val,
                };

                let y = match other.next() {
                    None => return Ordering::Greater,
                    Some(val) => val,
                };

                match cmp(x, y) {
                    Ordering::Equal => {}
                    non_eq => return non_eq,
                }
            }
        }

        // While sorting by map key, we get to assume that no two keys are
        // equal, otherwise they wouldn't both be in the map. This is not a safe
        // assumption outside of this situation.
        let total_cmp = |&(a, _): &_, &(b, _): &_| total_cmp(a, b);
        self_entries.sort_by(total_cmp);
        other_entries.sort_by(total_cmp);
        self_entries.partial_cmp(&other_entries)
    }
}

/// `Mapping` is ordered if its keys and values are ordered.
impl<I> std::ops::Index<I> for Mapping
where
    I: Index,
{
    type Output = Value;

    #[inline]
    #[track_caller]
    fn index(&self, index: I) -> &Value {
        index.index_into(self).unwrap()
    }
}

/// `Mapping` is ordered if its keys and values are ordered.
impl<I> std::ops::IndexMut<I> for Mapping
where
    I: Index,
{
    #[inline]
    #[track_caller]
    fn index_mut(&mut self, index: I) -> &mut Value {
        index.index_into_mut(self).unwrap()
    }
}

impl Extend<(Value, Value)> for Mapping {
    #[inline]
    fn extend<I: IntoIterator<Item = (Value, Value)>>(
        &mut self,
        iter: I,
    ) {
        self.map.extend(iter);
    }
}

impl FromIterator<(Value, Value)> for Mapping {
    #[inline]
    fn from_iter<I: IntoIterator<Item = (Value, Value)>>(
        iter: I,
    ) -> Self {
        Mapping {
            map: IndexMap::from_iter(iter),
        }
    }
}

macro_rules! delegate_iterator {
    (($name:ident $($generics:tt)*) => $item:ty) => {
        #[allow(single_use_lifetimes)]
        impl $($generics)* Iterator for $name $($generics)* {
            type Item = $item;
            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                self.iter.next()
            }
            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.iter.size_hint()
            }
        }

        #[allow(single_use_lifetimes)]
        impl $($generics)* ExactSizeIterator for $name $($generics)* {
            #[inline]
            fn len(&self) -> usize {
                self.iter.len()
            }
        }
    }
}

/// Iterator over `&serde_yml::Mapping`.
#[derive(Debug)]
pub struct Iter<'a> {
    iter: indexmap::map::Iter<'a, Value, Value>,
}

delegate_iterator!((Iter<'a>) => (&'a Value, &'a Value));

impl<'a> IntoIterator for &'a Mapping {
    type Item = (&'a Value, &'a Value);
    type IntoIter = Iter<'a>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Iter {
            iter: self.map.iter(),
        }
    }
}

/// Iterator over `&mut serde_yml::Mapping`.
#[derive(Debug)]
pub struct IterMut<'a> {
    iter: indexmap::map::IterMut<'a, Value, Value>,
}

delegate_iterator!((IterMut<'a>) => (&'a Value, &'a mut Value));

impl<'a> IntoIterator for &'a mut Mapping {
    type Item = (&'a Value, &'a mut Value);
    type IntoIter = IterMut<'a>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IterMut {
            iter: self.map.iter_mut(),
        }
    }
}

/// Iterator over `serde_yml::Mapping` by value.
#[derive(Debug)]
pub struct IntoIter {
    iter: indexmap::map::IntoIter<Value, Value>,
}

delegate_iterator!((IntoIter) => (Value, Value));

impl IntoIterator for Mapping {
    type Item = (Value, Value);
    type IntoIter = IntoIter;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            iter: self.map.into_iter(),
        }
    }
}

/// Iterator of the keys of a `&serde_yml::Mapping`.
#[derive(Debug)]
pub struct Keys<'a> {
    iter: indexmap::map::Keys<'a, Value, Value>,
}

delegate_iterator!((Keys<'a>) => &'a Value);

/// Iterator of the keys of a `serde_yml::Mapping`.
#[derive(Debug)]
pub struct IntoKeys {
    iter: indexmap::map::IntoKeys<Value, Value>,
}

delegate_iterator!((IntoKeys) => Value);

/// Iterator of the values of a `&serde_yml::Mapping`.
#[derive(Debug)]
pub struct Values<'a> {
    iter: indexmap::map::Values<'a, Value, Value>,
}

delegate_iterator!((Values<'a>) => &'a Value);

/// Iterator of the values of a `&mut serde_yml::Mapping`.
#[derive(Debug)]
pub struct ValuesMut<'a> {
    iter: indexmap::map::ValuesMut<'a, Value, Value>,
}

delegate_iterator!((ValuesMut<'a>) => &'a mut Value);

/// Iterator of the values of a `serde_yml::Mapping`.
#[derive(Debug)]
pub struct IntoValues {
    iter: indexmap::map::IntoValues<Value, Value>,
}

delegate_iterator!((IntoValues) => Value);

/// Entry for an existing key-value pair or a vacant location to insert one.
#[derive(Debug)]
pub enum Entry<'a> {
    /// Existing slot with equivalent key.
    Occupied(OccupiedEntry<'a>),
    /// Vacant slot (no equivalent key in the map).
    Vacant(VacantEntry<'a>),
}

/// A view into an occupied entry in a [`Mapping`]. It is part of the [`Entry`]
/// enum.
#[derive(Debug)]
pub struct OccupiedEntry<'a> {
    occupied: indexmap::map::OccupiedEntry<'a, Value, Value>,
}

/// A view into a vacant entry in a [`Mapping`]. It is part of the [`Entry`]
/// enum.
#[derive(Debug)]
pub struct VacantEntry<'a> {
    vacant: indexmap::map::VacantEntry<'a, Value, Value>,
}

impl<'a> Entry<'a> {
    /// Returns a reference to this entry's key.
    pub fn key(&self) -> &Value {
        match self {
            Entry::Vacant(e) => e.key(),
            Entry::Occupied(e) => e.key(),
        }
    }

    /// Ensures a value is in the entry by inserting the default if empty, and
    /// returns a mutable reference to the value in the entry.
    pub fn or_insert(self, default: Value) -> &'a mut Value {
        match self {
            Entry::Vacant(entry) => entry.insert(default),
            Entry::Occupied(entry) => entry.into_mut(),
        }
    }

    /// Ensures a value is in the entry by inserting the result of the default
    /// function if empty, and returns a mutable reference to the value in the
    /// entry.
    pub fn or_insert_with<F>(self, default: F) -> &'a mut Value
    where
        F: FnOnce() -> Value,
    {
        match self {
            Entry::Vacant(entry) => entry.insert(default()),
            Entry::Occupied(entry) => entry.into_mut(),
        }
    }

    /// Provides in-place mutable access to an occupied entry before any
    /// potential inserts into the map.
    pub fn and_modify<F>(self, f: F) -> Self
    where
        F: FnOnce(&mut Value),
    {
        match self {
            Entry::Occupied(mut entry) => {
                f(entry.get_mut());
                Entry::Occupied(entry)
            }
            Entry::Vacant(entry) => Entry::Vacant(entry),
        }
    }
}

impl<'a> OccupiedEntry<'a> {
    /// Gets a reference to the key in the entry.
    #[inline]
    pub fn key(&self) -> &Value {
        self.occupied.key()
    }

    /// Gets a reference to the value in the entry.
    #[inline]
    pub fn get(&self) -> &Value {
        self.occupied.get()
    }

    /// Gets a mutable reference to the value in the entry.
    #[inline]
    pub fn get_mut(&mut self) -> &mut Value {
        self.occupied.get_mut()
    }

    /// Converts the entry into a mutable reference to its value.
    #[inline]
    pub fn into_mut(self) -> &'a mut Value {
        self.occupied.into_mut()
    }

    /// Sets the value of the entry with the `OccupiedEntry`'s key, and returns
    /// the entry's old value.
    #[inline]
    pub fn insert(&mut self, value: Value) -> Value {
        self.occupied.insert(value)
    }

    /// Takes the value of the entry out of the map, and returns it.
    #[inline]
    pub fn remove(self) -> Value {
        self.occupied.swap_remove()
    }

    /// Remove and return the key, value pair stored in the map for this entry.
    #[inline]
    pub fn remove_entry(self) -> (Value, Value) {
        self.occupied.swap_remove_entry()
    }
}

impl<'a> VacantEntry<'a> {
    /// Gets a reference to the key that would be used when inserting a value
    /// through the VacantEntry.
    #[inline]
    pub fn key(&self) -> &Value {
        self.vacant.key()
    }

    /// Takes ownership of the key, leaving the entry vacant.
    #[inline]
    pub fn into_key(self) -> Value {
        self.vacant.into_key()
    }

    /// Sets the value of the entry with the VacantEntry's key, and returns a
    /// mutable reference to it.
    #[inline]
    pub fn insert(self, value: Value) -> &'a mut Value {
        self.vacant.insert(value)
    }
}

/// `Mapping` implements `Serialize` using the `serde` crate.
impl Serialize for Mapping {
    #[inline]
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map_serializer =
            serializer.serialize_map(Some(self.len()))?;
        for (k, v) in self {
            map_serializer.serialize_entry(k, v)?;
        }
        map_serializer.end()
    }
}

/// `Mapping` implements `Deserialize` using the `serde` crate.
impl<'de> Deserialize<'de> for Mapping {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Mapping;

            fn expecting(
                &self,
                formatter: &mut fmt::Formatter<'_>,
            ) -> fmt::Result {
                formatter.write_str("a YAML mapping")
            }

            #[inline]
            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Mapping::new())
            }

            #[inline]
            fn visit_map<A>(
                self,
                mut data: A,
            ) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut mapping = Mapping::new();

                while let Some(key) = data.next_key()? {
                    match mapping.entry(key) {
                        Entry::Occupied(entry) => {
                            return Err(serde::de::Error::custom(
                                DuplicateKeyError { entry },
                            ));
                        }
                        Entry::Vacant(entry) => {
                            let value = data.next_value()?;
                            entry.insert(value);
                        }
                    }
                }

                Ok(mapping)
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

#[derive(Debug)]
/// Error returned when a duplicate key is encountered while deserializing a
/// `serde_yml::Mapping`.
///
/// This error contains the key-value pair that caused the conflict.
pub struct DuplicateKeyError<'a> {
    /// The key-value pair that caused the conflict.
    pub entry: OccupiedEntry<'a>,
}

/// `DuplicateKeyError` implements `Display` to provide a human-readable error
impl Display for DuplicateKeyError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("duplicate entry ")?;
        match self.entry.key() {
            Value::Null => formatter.write_str("with null key"),
            Value::Bool(boolean) => {
                write!(formatter, "with key `{}`", boolean)
            }
            Value::Number(number) => {
                write!(formatter, "with key {}", number)
            }
            Value::String(string) => {
                write!(formatter, "with key {:?}", string)
            }
            Value::Sequence(_)
            | Value::Mapping(_)
            | Value::Tagged(_) => formatter.write_str("in YAML map"),
        }
    }
}
