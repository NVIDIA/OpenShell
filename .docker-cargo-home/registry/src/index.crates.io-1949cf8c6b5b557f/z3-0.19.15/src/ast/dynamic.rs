use crate::ast::{Array, Ast, BV, Bool, Datatype, Float, Int, Real, Seq, Set};
use crate::{Context, Sort, Symbol, ast};
use std::ffi::CString;
use z3_sys::*;

/// A dynamically typed [`Ast`] node.
pub struct Dynamic {
    pub(crate) ctx: Context,
    pub(crate) z3_ast: Z3_ast,
}

impl Dynamic {
    pub fn from_ast(ast: &dyn Ast) -> Self {
        unsafe { Self::wrap(ast.get_ctx(), ast.get_z3_ast()) }
    }

    pub fn new_const<S: Into<Symbol>>(name: S, sort: &Sort) -> Self {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(
                ctx,
                Z3_mk_const(ctx.z3_ctx.0, name.into().as_z3_symbol(), sort.z3_sort).unwrap(),
            )
        }
    }

    pub fn fresh_const(prefix: &str, sort: &Sort) -> Self {
        let ctx = sort.ctx.clone();
        unsafe {
            Self::wrap(&ctx, {
                let pp = CString::new(prefix).unwrap();
                let p = pp.as_ptr();
                Z3_mk_fresh_const(ctx.z3_ctx.0, p, sort.z3_sort).unwrap()
            })
        }
    }

    pub fn sort_kind(&self) -> SortKind {
        unsafe {
            Z3_get_sort_kind(
                self.ctx.z3_ctx.0,
                Z3_get_sort(self.ctx.z3_ctx.0, self.z3_ast).unwrap(),
            )
        }
    }

    /// Returns `None` if the `Dynamic` is not actually a `Bool`
    pub fn as_bool(&self) -> Option<Bool> {
        match self.sort_kind() {
            SortKind::Bool => Some(unsafe { Bool::wrap(&self.ctx, self.z3_ast) }),
            _ => None,
        }
    }

    /// Returns `None` if the `Dynamic` is not actually an `Int`
    pub fn as_int(&self) -> Option<Int> {
        match self.sort_kind() {
            SortKind::Int => Some(unsafe { Int::wrap(&self.ctx, self.z3_ast) }),
            _ => None,
        }
    }

    /// Returns `None` if the `Dynamic` is not actually a `Real`
    pub fn as_real(&self) -> Option<Real> {
        match self.sort_kind() {
            SortKind::Real => Some(unsafe { Real::wrap(&self.ctx, self.z3_ast) }),
            _ => None,
        }
    }

    /// Returns `None` if the `Dynamic` is not actually a `Float`
    pub fn as_float(&self) -> Option<Float> {
        match self.sort_kind() {
            SortKind::FloatingPoint => Some(unsafe { Float::wrap(&self.ctx, self.z3_ast) }),
            _ => None,
        }
    }

    /// Returns `None` if the `Dynamic` is not actually a `String`
    pub fn as_string(&self) -> Option<ast::String> {
        unsafe {
            if Z3_is_string_sort(
                self.ctx.z3_ctx.0,
                Z3_get_sort(self.ctx.z3_ctx.0, self.z3_ast)?,
            ) {
                Some(ast::String::wrap(&self.ctx, self.z3_ast))
            } else {
                None
            }
        }
    }

    /// Returns `None` if the `Dynamic` is not actually a `BV`
    pub fn as_bv(&self) -> Option<BV> {
        match self.sort_kind() {
            SortKind::BV => Some(unsafe { BV::wrap(&self.ctx, self.z3_ast) }),
            _ => None,
        }
    }

    /// Returns `None` if the `Dynamic` is not actually an `Array`
    pub fn as_array(&self) -> Option<Array> {
        match self.sort_kind() {
            SortKind::Array => Some(unsafe { Array::wrap(&self.ctx, self.z3_ast) }),
            _ => None,
        }
    }

    /// Returns `None` if the `Dynamic` is not actually a `Set`
    pub fn as_set(&self) -> Option<Set> {
        unsafe {
            match self.sort_kind() {
                SortKind::Array => {
                    match Z3_get_sort_kind(
                        self.ctx.z3_ctx.0,
                        Z3_get_array_sort_range(
                            self.ctx.z3_ctx.0,
                            Z3_get_sort(self.ctx.z3_ctx.0, self.z3_ast)?,
                        )?,
                    ) {
                        SortKind::Bool => Some(Set::wrap(&self.ctx, self.z3_ast)),
                        _ => None,
                    }
                }
                _ => None,
            }
        }
    }

    /// Returns `None` if the `Dynamic` is not actually a `Seq`.
    pub fn as_seq(&self) -> Option<Seq> {
        match self.sort_kind() {
            SortKind::Seq => Some(unsafe { Seq::wrap(&self.ctx, self.z3_ast) }),
            _ => None,
        }
    }

    /// Returns `None` if the `Dynamic` is not actually a `Datatype`
    pub fn as_datatype(&self) -> Option<Datatype> {
        match self.sort_kind() {
            SortKind::Datatype => Some(unsafe { Datatype::wrap(&self.ctx, self.z3_ast) }),
            _ => None,
        }
    }
}
