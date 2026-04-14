use crate::ast::{Ast, Dynamic};
use crate::{Context, Sort, Symbol};
use std::ffi::CString;
use z3_sys::*;

/// [`Ast`] node representing an array value.
/// An array in Z3 is a mapping from indices to values.
pub struct Array {
    pub(crate) ctx: Context,
    pub(crate) z3_ast: Z3_ast,
}

impl Array {
    /// Create an `Array` which maps from indices of the `domain` `Sort` to
    /// values of the `range` `Sort`.
    ///
    /// All values in the `Array` will be unconstrained.
    pub fn new_const<S: Into<Symbol>>(name: S, domain: &Sort, range: &Sort) -> Array {
        let ctx = &Context::thread_local();
        let sort = Sort::array(domain, range);
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_const(ctx.z3_ctx.0, name.into().as_z3_symbol(), sort.z3_sort).unwrap()
            })
        }
    }

    pub fn fresh_const(prefix: &str, domain: &Sort, range: &Sort) -> Array {
        let ctx = &Context::thread_local();
        let sort = Sort::array(domain, range);
        unsafe {
            Self::wrap(ctx, {
                let pp = CString::new(prefix).unwrap();
                let p = pp.as_ptr();
                Z3_mk_fresh_const(ctx.z3_ctx.0, p, sort.z3_sort).unwrap()
            })
        }
    }

    /// Create a "constant array", that is, an `Array` initialized so that all of the
    /// indices in the `domain` map to the given value `val`
    pub fn const_array<A>(domain: &Sort, val: &A) -> Array
    where
        A: Ast,
    {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_const_array(ctx.z3_ctx.0, domain.z3_sort, val.get_z3_ast()).unwrap()
            })
        }
    }

    /// Get the value at a given index in the array.
    ///
    /// Note that the `index` _must be_ of the array's `domain` sort.
    /// The return type will be of the array's `range` sort.
    //
    // We avoid the binop! macro because the argument has a non-Self type
    pub fn select<A>(&self, index: &A) -> Dynamic
    where
        A: Ast,
    {
        // TODO: We could validate here that the index is of the correct type.
        // This would require us either to keep around the original `domain` argument
        // from when the Array was constructed, or to do an additional Z3 query
        // to find the domain sort first.
        // But if we did this check ourselves, we'd just panic, so it doesn't seem
        // like a huge advantage over just letting Z3 panic itself when it discovers the
        // problem.
        // This way we also avoid the redundant check every time this method is called.
        unsafe {
            Dynamic::wrap(&self.ctx, {
                Z3_mk_select(self.ctx.z3_ctx.0, self.z3_ast, index.get_z3_ast()).unwrap()
            })
        }
    }

    /// n-ary Array read. `idxs` are the indices of the array that gets read.
    /// This is useful for applying lambdas.
    pub fn select_n(&self, idxs: &[&dyn Ast]) -> Dynamic {
        let idxs: Vec<_> = idxs.iter().map(|idx| idx.get_z3_ast()).collect();

        unsafe {
            Dynamic::wrap(&self.ctx, {
                Z3_mk_select_n(
                    self.ctx.z3_ctx.0,
                    self.z3_ast,
                    idxs.len().try_into().unwrap(),
                    idxs.as_ptr() as *const Z3_ast,
                )
                .unwrap()
            })
        }
    }

    /// Update the value at a given index in the array.
    ///
    /// Note that the `index` _must be_ of the array's `domain` sort,
    /// and the `value` _must be_ of the array's `range` sort.
    //
    // We avoid the trinop! macro because the arguments have non-Self types
    pub fn store<A1, A2>(&self, index: &A1, value: &A2) -> Self
    where
        A1: Ast,
        A2: Ast,
    {
        unsafe {
            Self::wrap(&self.ctx, {
                Z3_mk_store(
                    self.ctx.z3_ctx.0,
                    self.z3_ast,
                    index.get_z3_ast(),
                    value.get_z3_ast(),
                )
                .unwrap()
            })
        }
    }

    /// Returns true if the array is a const array (i.e. `a.is_const_array() => exists v, forall i. select(a, i) == v`)
    ///
    /// # Examples
    /// ```
    /// # use z3::{ast, Config, Context, ast::{Array, Int}, Sort};
    /// # use z3::ast::Ast;
    /// # use std::convert::TryInto;
    /// let arr = Array::const_array(&Sort::int(), &Int::from_u64(9));
    /// assert!(arr.is_const_array());
    /// let arr2 = Array::fresh_const("a", &Sort::int(), &Sort::int());
    /// assert!(!arr2.is_const_array());
    /// ```
    pub fn is_const_array(&self) -> bool {
        // python:
        // is_app_of(a, Z3_OP_CONST_ARRAY)
        // >> is_app(a) and a.decl().kind() == Z3_OP_CONST_ARRAY
        self.is_app() && matches!(self.decl().kind(), DeclKind::CONST_ARRAY)
    }
}
