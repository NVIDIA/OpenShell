use crate::Context;
use crate::ast::{Ast, Real};
use std::convert::TryFrom;
use z3_sys::*;

/// [`Ast`] node representing a real algebraic number value.
///
/// `Algebraic` is a sub-sort of [`Real`]: every algebraic number is a real number,
/// but not every real is algebraic. Use [`From<Algebraic>`] to widen to `Real`,
/// or [`TryFrom<Real>`] to narrow (fails if the `Real` is not a concrete algebraic value).
pub struct Algebraic {
    pub(crate) ctx: Context,
    pub(crate) z3_ast: Z3_ast,
}

impl Algebraic {
    /// Check if the given AST is a value in the Z3 real algebraic number package.
    pub fn is_value(ast: &impl Ast) -> bool {
        unsafe { Z3_algebraic_is_value(ast.get_ctx().z3_ctx.0, ast.get_z3_ast()) }
    }

    /// Check if the algebraic number is positive.
    pub fn is_positive(&self) -> bool {
        unsafe { Z3_algebraic_is_pos(self.ctx.z3_ctx.0, self.z3_ast) }
    }

    /// Check if the algebraic number is negative.
    pub fn is_negative(&self) -> bool {
        unsafe { Z3_algebraic_is_neg(self.ctx.z3_ctx.0, self.z3_ast) }
    }

    /// Check if the algebraic number is zero.
    pub fn is_zero(&self) -> bool {
        unsafe { Z3_algebraic_is_zero(self.ctx.z3_ctx.0, self.z3_ast) }
    }

    /// Return the sign of the algebraic number: -1 if negative, 0 if zero, 1 if positive.
    pub fn sign(&self) -> i32 {
        unsafe { Z3_algebraic_sign(self.ctx.z3_ctx.0, self.z3_ast) }
    }

    /// Add two algebraic numbers.
    pub fn add(a: &Algebraic, b: &Algebraic) -> Algebraic {
        assert_eq!(a.ctx.z3_ctx, b.ctx.z3_ctx);
        unsafe {
            Algebraic::wrap(
                &a.ctx,
                Z3_algebraic_add(a.ctx.z3_ctx.0, a.z3_ast, b.z3_ast).unwrap(),
            )
        }
    }

    /// Subtract two algebraic numbers.
    pub fn sub(a: &Algebraic, b: &Algebraic) -> Algebraic {
        assert_eq!(a.ctx.z3_ctx, b.ctx.z3_ctx);
        unsafe {
            Algebraic::wrap(
                &a.ctx,
                Z3_algebraic_sub(a.ctx.z3_ctx.0, a.z3_ast, b.z3_ast).unwrap(),
            )
        }
    }

    /// Multiply two algebraic numbers.
    pub fn mul(a: &Algebraic, b: &Algebraic) -> Algebraic {
        assert_eq!(a.ctx.z3_ctx, b.ctx.z3_ctx);
        unsafe {
            Algebraic::wrap(
                &a.ctx,
                Z3_algebraic_mul(a.ctx.z3_ctx.0, a.z3_ast, b.z3_ast).unwrap(),
            )
        }
    }

    /// Divide two algebraic numbers.
    pub fn div(a: &Algebraic, b: &Algebraic) -> Algebraic {
        assert_eq!(a.ctx.z3_ctx, b.ctx.z3_ctx);
        unsafe {
            Algebraic::wrap(
                &a.ctx,
                Z3_algebraic_div(a.ctx.z3_ctx.0, a.z3_ast, b.z3_ast).unwrap(),
            )
        }
    }

    /// Return the k-th root of the algebraic number. Requires k > 0.
    pub fn root(&self, k: u32) -> Algebraic {
        unsafe {
            Algebraic::wrap(
                &self.ctx,
                Z3_algebraic_root(self.ctx.z3_ctx.0, self.z3_ast, k).unwrap(),
            )
        }
    }

    /// Return this algebraic number raised to the k-th power.
    pub fn power(&self, k: u32) -> Algebraic {
        unsafe {
            Algebraic::wrap(
                &self.ctx,
                Z3_algebraic_power(self.ctx.z3_ctx.0, self.z3_ast, k).unwrap(),
            )
        }
    }

    /// Return true if `a < b`.
    pub fn lt(a: &Algebraic, b: &Algebraic) -> bool {
        assert_eq!(a.ctx.z3_ctx, b.ctx.z3_ctx);
        unsafe { Z3_algebraic_lt(a.ctx.z3_ctx.0, a.z3_ast, b.z3_ast) }
    }

    /// Return true if `a > b`.
    pub fn gt(a: &Algebraic, b: &Algebraic) -> bool {
        assert_eq!(a.ctx.z3_ctx, b.ctx.z3_ctx);
        unsafe { Z3_algebraic_gt(a.ctx.z3_ctx.0, a.z3_ast, b.z3_ast) }
    }

    /// Return true if `a == b` (algebraic equality).
    pub fn eq_algebraic(a: &Algebraic, b: &Algebraic) -> bool {
        assert_eq!(a.ctx.z3_ctx, b.ctx.z3_ctx);
        unsafe { Z3_algebraic_eq(a.ctx.z3_ctx.0, a.z3_ast, b.z3_ast) }
    }
}

impl From<Algebraic> for Real {
    fn from(a: Algebraic) -> Real {
        unsafe { Real::wrap(&a.ctx, a.z3_ast) }
    }
}

impl TryFrom<Real> for Algebraic {
    type Error = ();

    /// Returns `Ok(Algebraic)` if the `Real` is a concrete algebraic value,
    /// or `Err(())` if it is a symbolic expression.
    fn try_from(real: Real) -> Result<Self, ()> {
        if Algebraic::is_value(&real) {
            Ok(unsafe { Algebraic::wrap(&real.ctx, real.z3_ast) })
        } else {
            Err(())
        }
    }
}
