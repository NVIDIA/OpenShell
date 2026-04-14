use std::convert::TryFrom;
use std::fmt;
use std::iter::FusedIterator;

use crate::Context;
use crate::ast::{Array, Ast, BV, Bool, Dynamic, Float, Int, Real, Seq, Set};
use crate::ast::{Datatype, String as AstString};
use z3_sys::*;

/// Vector of Z3 AST nodes.
///
/// This wraps a Z3-ref-counted vector of asts. This type exists
/// mainly as a high-level compatibility layer for these types from Rust.
/// As this type wraps heterogenous asts, it is analagous to `Vec<Dynamic>`.
///
/// Most users will usually be better off using a [Vec]; this type primarily
/// exists as a compatibility shim.
///
/// Many standard rust collection and iteration traits are implemented on it
/// for convenience.
pub struct AstVector {
    pub(crate) ctx: Context,
    pub(crate) z3_ast_vector: Z3_ast_vector,
}

impl Drop for AstVector {
    fn drop(&mut self) {
        unsafe {
            Z3_ast_vector_dec_ref(self.ctx.z3_ctx.0, self.z3_ast_vector);
        }
    }
}

impl AstVector {
    /// Create a new empty AST vector.
    pub fn new() -> AstVector {
        let ctx = Context::thread_local();
        unsafe {
            let av = Z3_mk_ast_vector(ctx.z3_ctx.0).unwrap();
            Z3_ast_vector_inc_ref(ctx.z3_ctx.0, av);
            AstVector {
                ctx: ctx.clone(),
                z3_ast_vector: av,
            }
        }
    }

    /// Wrap an existing Z3 AST vector.
    pub(crate) unsafe fn wrap(ctx: &Context, z3_ast_vector: Z3_ast_vector) -> AstVector {
        unsafe {
            Z3_ast_vector_inc_ref(ctx.z3_ctx.0, z3_ast_vector);
        }
        AstVector {
            ctx: ctx.clone(),
            z3_ast_vector,
        }
    }

    /// Get the number of elements in the vector.
    pub fn len(&self) -> usize {
        unsafe { Z3_ast_vector_size(self.ctx.z3_ctx.0, self.z3_ast_vector) as usize }
    }

    /// Check if the vector is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the element at the specified index.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds.
    pub fn get(&self, index: usize) -> Dynamic {
        assert!(index < self.len(), "Index {index} out of bounds");
        unsafe {
            Dynamic::wrap(
                &self.ctx,
                Z3_ast_vector_get(self.ctx.z3_ctx.0, self.z3_ast_vector, index as u32).unwrap(),
            )
        }
    }

    /// Set the element at the specified index.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds.
    pub fn set(&self, index: usize, ast: &impl Ast) {
        assert!(index < self.len(), "Index {index} out of bounds");
        unsafe {
            Z3_ast_vector_set(
                self.ctx.z3_ctx.0,
                self.z3_ast_vector,
                index as u32,
                ast.get_z3_ast(),
            );
        }
    }

    /// Push an element to the end of the vector.
    pub fn push(&self, ast: &impl Ast) {
        unsafe {
            Z3_ast_vector_push(self.ctx.z3_ctx.0, self.z3_ast_vector, ast.get_z3_ast());
        }
    }

    /// Resize the vector to the specified size.
    ///
    /// New elements (if any) are uninitialized.
    pub fn resize(&self, new_size: usize) {
        unsafe {
            Z3_ast_vector_resize(self.ctx.z3_ctx.0, self.z3_ast_vector, new_size as u32);
        }
    }

    /// Convert the vector to a `Vec<Dynamic>`.
    pub fn to_vec(&self) -> Vec<Dynamic> {
        self.iter().collect()
    }

    /// Translate the AST vector to another context.
    pub fn translate(&self, target_ctx: &Context) -> AstVector {
        unsafe {
            AstVector::wrap(
                target_ctx,
                Z3_ast_vector_translate(self.ctx.z3_ctx.0, self.z3_ast_vector, target_ctx.z3_ctx.0)
                    .unwrap(),
            )
        }
    }

    /// Return a borrowing iterator over the elements.
    pub fn iter(&self) -> AstVectorIter<'_> {
        AstVectorIter {
            vector: self,
            index: 0,
            end: self.len(),
        }
    }

    /// Try to convert every element to the concrete AST type `T`.
    ///
    /// Returns `Err` with the first conversion failure message if any element
    /// cannot be cast to `T`.
    fn try_into_typed_vec<T>(self) -> Result<Vec<T>, String>
    where
        T: TryFrom<Dynamic, Error = String>,
    {
        self.into_iter().map(T::try_from).collect()
    }
}

impl Default for AstVector {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AstVector {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let s = unsafe {
            let raw = Z3_ast_vector_to_string(self.ctx.z3_ctx.0, self.z3_ast_vector);
            std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned()
        };
        write!(f, "{s}")
    }
}

impl fmt::Debug for AstVector {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// Borrowing iterator
// ---------------------------------------------------------------------------

/// Borrowing iterator over [`AstVector`] elements.
#[derive(Debug)]
pub struct AstVectorIter<'a> {
    vector: &'a AstVector,
    index: usize,
    end: usize,
}

impl<'a> Iterator for AstVectorIter<'a> {
    type Item = Dynamic;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.end {
            let item = self.vector.get(self.index);
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for AstVectorIter<'_> {}
impl FusedIterator for AstVectorIter<'_> {}

impl<'a> IntoIterator for &'a AstVector {
    type Item = Dynamic;
    type IntoIter = AstVectorIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// ---------------------------------------------------------------------------
// Consuming iterator
// ---------------------------------------------------------------------------

/// Consuming iterator over [`AstVector`] elements.
#[derive(Debug)]
pub struct AstVectorIntoIter {
    vector: AstVector,
    index: usize,
    end: usize,
}

impl Iterator for AstVectorIntoIter {
    type Item = Dynamic;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.end {
            let item = self.vector.get(self.index);
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for AstVectorIntoIter {}
impl FusedIterator for AstVectorIntoIter {}

impl IntoIterator for AstVector {
    type Item = Dynamic;
    type IntoIter = AstVectorIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        let end = self.len();
        AstVectorIntoIter {
            vector: self,
            index: 0,
            end,
        }
    }
}

// ---------------------------------------------------------------------------
// FromIterator / From
// ---------------------------------------------------------------------------

impl<T: Ast> FromIterator<T> for AstVector {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let vector = AstVector::new();
        for item in iter {
            vector.push(&item);
        }
        vector
    }
}

impl<T: Ast> From<Vec<T>> for AstVector {
    fn from(v: Vec<T>) -> Self {
        v.into_iter().collect()
    }
}

/// Build an [`AstVector`] from a borrowed slice, avoiding clones.
impl<T: Ast> From<&[T]> for AstVector {
    fn from(slice: &[T]) -> Self {
        let vector = AstVector::new();
        for item in slice {
            vector.push(item);
        }
        vector
    }
}

// ---------------------------------------------------------------------------
// TryFrom<AstVector> for Vec<ConcreteAst>
//
// `AstVector` is a local type appearing as an uncovered type argument to
// the foreign trait `TryFrom`, satisfying the orphan rule.
// ---------------------------------------------------------------------------

macro_rules! impl_try_from_ast_vector {
    ($T:ty) => {
        impl TryFrom<AstVector> for Vec<$T> {
            type Error = String;

            fn try_from(v: AstVector) -> Result<Self, Self::Error> {
                v.try_into_typed_vec()
            }
        }
    };
}

impl_try_from_ast_vector!(Bool);
impl_try_from_ast_vector!(Int);
impl_try_from_ast_vector!(Real);
impl_try_from_ast_vector!(Float);
impl_try_from_ast_vector!(BV);
impl_try_from_ast_vector!(Array);
impl_try_from_ast_vector!(Set);
impl_try_from_ast_vector!(Seq);
impl_try_from_ast_vector!(Datatype);
impl_try_from_ast_vector!(AstString);
