use crate::ast::{Ast, Bool};
use crate::{AstVector, Model};
use z3_sys::*;

/// Quantifier elimination using Z3's built-in QE APIs.
#[derive(Debug)]
pub struct QuantifierElimination;

impl QuantifierElimination {
    /// Best-effort quantifier elimination for the listed variables.
    ///
    /// `vars` — the variables to eliminate; `formula` — the formula body
    /// (no quantifier wrapper needed).
    pub fn lite(vars: &AstVector, formula: &impl Ast) -> Bool {
        let ctx = formula.get_ctx();
        unsafe {
            Bool::wrap(
                ctx,
                Z3_qe_lite(ctx.z3_ctx.0, vars.z3_ast_vector, formula.get_z3_ast()).unwrap(),
            )
        }
    }

    /// Project variables from a formula using model-guided quantifier elimination.
    ///
    /// Eliminates `vars` from `formula` by exploiting a concrete `model`.
    /// The variables must be uninterpreted constants (0-arity function applications).
    pub fn model_project(model: &Model, vars: &[&dyn Ast], formula: &impl Ast) -> Bool {
        let ctx = formula.get_ctx();
        unsafe {
            let z3_vars: Vec<Z3_app> = vars
                .iter()
                .map(|v| Z3_to_app(ctx.z3_ctx.0, v.get_z3_ast()).unwrap())
                .collect();
            Bool::wrap(
                ctx,
                Z3_qe_model_project(
                    ctx.z3_ctx.0,
                    model.z3_mdl,
                    z3_vars.len() as u32,
                    z3_vars.as_ptr(),
                    formula.get_z3_ast(),
                )
                .unwrap(),
            )
        }
    }
}
