use crate::ast::Ast;
use crate::ast_vector::AstVector;
use z3_sys::*;

/// Polynomial operations for Z3 expressions.
#[derive(Debug)]
pub struct Polynomial;

impl Polynomial {
    /// Compute the nonzero subresultants of polynomials `p` and `q` with respect to variable `x`.
    ///
    /// Both `p` and `q` are arithmetic terms where any subterm that cannot be viewed
    /// as a polynomial is assumed to be a variable.
    ///
    /// For example, `f(a)` is considered to be a variable in the polynomial `f(a)*f(a) + 2*f(a) + 1`.
    ///
    /// Returns an [`AstVector`] containing the nonzero subresultants.
    ///
    /// # Example
    /// ```
    /// # use z3::ast::*;
    /// let x = Int::new_const("x");
    /// let y = Int::new_const("y");
    /// let p1 = &x * &x + &x + 1;  // x^2 + x + 1
    /// let p2 = &x + &y;           // x + y
    /// let subresultants = Polynomial::subresultants(&p1, &p2, &x);
    /// ```
    pub fn subresultants(p: &impl Ast, q: &impl Ast, x: &impl Ast) -> AstVector {
        assert_eq!(p.get_ctx().z3_ctx, q.get_ctx().z3_ctx);
        assert_eq!(p.get_ctx().z3_ctx, x.get_ctx().z3_ctx);

        let ctx = p.get_ctx();
        unsafe {
            AstVector::wrap(
                ctx,
                Z3_polynomial_subresultants(
                    ctx.z3_ctx.0,
                    p.get_z3_ast(),
                    q.get_z3_ast(),
                    x.get_z3_ast(),
                )
                .unwrap(),
            )
        }
    }
}
