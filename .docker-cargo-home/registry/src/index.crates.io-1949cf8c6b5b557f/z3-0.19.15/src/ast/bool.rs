use crate::ast::{Ast, binop, unop, varop};
use crate::{Context, Sort, Symbol};
use std::ffi::CString;
use z3_sys::*;

/// [`Ast`] node representing a boolean value.
pub struct Bool {
    pub(crate) ctx: Context,
    pub(crate) z3_ast: Z3_ast,
}
impl Bool {
    pub fn new_const<S: Into<Symbol>>(name: S) -> Bool {
        let ctx = &Context::thread_local();
        let sort = Sort::bool();
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_const(ctx.z3_ctx.0, name.into().as_z3_symbol(), sort.z3_sort).unwrap()
            })
        }
    }

    /// Declare and create a fresh Boolean uninterpreted constant with name `prefix`.
    pub fn fresh_const(prefix: &str) -> Bool {
        let ctx = &Context::thread_local();
        let sort = Sort::bool();
        unsafe {
            Self::wrap(ctx, {
                let pp = CString::new(prefix).unwrap();
                let p = pp.as_ptr();
                Z3_mk_fresh_const(ctx.z3_ctx.0, p, sort.z3_sort).unwrap()
            })
        }
    }

    /// Create an AST node representing `true` or `false`.
    pub fn from_bool(b: bool) -> Bool {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(ctx, {
                if b {
                    Z3_mk_true(ctx.z3_ctx.0).unwrap()
                } else {
                    Z3_mk_false(ctx.z3_ctx.0).unwrap()
                }
            })
        }
    }

    /// If `self` is the Boolean value `true` or `false`, return its value. Otherwise, return [None].
    pub fn as_bool(&self) -> Option<bool> {
        unsafe {
            match Z3_get_bool_value(self.ctx.z3_ctx.0, self.z3_ast) {
                Z3_L_TRUE => Some(true),
                Z3_L_FALSE => Some(false),
                _ => None,
            }
        }
    }

    /// Uses `self` as a predicate in an if-then-else expression. Evaluates to `then_expr` when `self` is true.
    pub fn ite<T>(&self, then_expr: &T, else_expr: &T) -> T
    where
        T: Ast,
    {
        unsafe {
            T::wrap(&self.ctx, {
                Z3_mk_ite(
                    self.ctx.z3_ctx.0,
                    self.z3_ast,
                    then_expr.get_z3_ast(),
                    else_expr.get_z3_ast(),
                )
                .unwrap()
            })
        }
    }

    varop! {
        /// Creates an AST node that is the logical AND of two expressions
        and(Z3_mk_and, Self);
        /// Creates an AST node that is the logical OR of two expressions
        or(Z3_mk_or, Self);
    }
    binop! {
        /// Creates an AST node that is the logical XOR of `self` and some other expression
        xor(Z3_mk_xor, Self);
        /// Creates an AST node that is the logical XNOR of `self` and some other expression
        iff(Z3_mk_iff, Self);
        /// Creates an AST node that is the logical implication of `self` with some other expression
        implies(Z3_mk_implies, Self);
    }
    unop! {
        /// Creates an AST node that is the logical NOT of `self`
        not(Z3_mk_not, Self);
    }

    /// Creates an at-most Pseudo-Boolean k constraint:
    /// `values[0].0 * values[0].1 + ... + values[n - 1].0 * values[n - 1].1 <= k`
    ///
    /// # See also:
    ///
    /// - [`crate::ast::atmost()`]
    pub fn pb_le(values: &[(&Bool, i32)], k: i32) -> Bool {
        let ctx = &Context::thread_local();
        unsafe {
            Bool::wrap(ctx, {
                assert!(values.len() <= 0xffffffff);
                let (values, coefficients): (Vec<Z3_ast>, Vec<i32>) = values
                    .iter()
                    .map(|(boolean, coefficient)| (boolean.z3_ast, coefficient))
                    .unzip();
                Z3_mk_pble(
                    ctx.z3_ctx.0,
                    values.len() as u32,
                    values.as_ptr(),
                    coefficients.as_ptr(),
                    k,
                )
                .unwrap()
            })
        }
    }

    /// Creates an at-least Pseudo-Boolean k constraint:
    /// `values[0].0 * values[0].1 + ... + values[n - 1].0 * values[n - 1].1 >= k`
    ///
    /// # See also:
    ///
    /// - [`crate::ast::atleast()`]
    pub fn pb_ge(values: &[(&Bool, i32)], k: i32) -> Bool {
        let ctx = &Context::thread_local();
        unsafe {
            Bool::wrap(ctx, {
                assert!(values.len() <= 0xffffffff);
                let (values, coefficients): (Vec<Z3_ast>, Vec<i32>) = values
                    .iter()
                    .map(|(boolean, coefficient)| (boolean.z3_ast, coefficient))
                    .unzip();
                Z3_mk_pbge(
                    ctx.z3_ctx.0,
                    values.len() as u32,
                    values.as_ptr(),
                    coefficients.as_ptr(),
                    k,
                )
                .unwrap()
            })
        }
    }

    /// Creates a Pseudo-Boolean k constraint:
    /// `values[0].0 * values[0].1 + ... + values[n - 1].0 * values[n - 1].1 == k`
    pub fn pb_eq(values: &[(&Bool, i32)], k: i32) -> Bool {
        let ctx = &Context::thread_local();
        unsafe {
            Bool::wrap(ctx, {
                assert!(values.len() <= 0xffffffff);
                let (values, coefficients): (Vec<Z3_ast>, Vec<i32>) = values
                    .iter()
                    .map(|(boolean, coefficient)| (boolean.z3_ast, coefficient))
                    .unzip();
                Z3_mk_pbeq(
                    ctx.z3_ctx.0,
                    values.len() as u32,
                    values.as_ptr(),
                    coefficients.as_ptr(),
                    k,
                )
                .unwrap()
            })
        }
    }
}
