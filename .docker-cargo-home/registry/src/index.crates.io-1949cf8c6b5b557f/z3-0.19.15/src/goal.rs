use std::ffi::CStr;
use std::fmt;
use z3_sys::*;

use crate::ast::Bool;
use crate::{Context, Goal, Translate, ast, ast::Ast};

// todo: is this sound? This should be through `wrap`, no?
impl Clone for Goal {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            z3_goal: self.z3_goal,
        }
    }
}

impl Goal {
    pub(crate) unsafe fn wrap(ctx: &Context, z3_goal: Z3_goal) -> Goal {
        unsafe {
            Z3_goal_inc_ref(ctx.z3_ctx.0, z3_goal);
        }
        Goal {
            ctx: ctx.clone(),
            z3_goal,
        }
    }

    pub fn new(models: bool, unsat_cores: bool, proofs: bool) -> Goal {
        let ctx = &Context::thread_local();
        // NOTE: The Z3 context ctx must have been created with proof generation support.
        unsafe {
            Self::wrap(
                ctx,
                Z3_mk_goal(ctx.z3_ctx.0, models, unsat_cores, proofs).unwrap(),
            )
        }
    }

    /// Add a new formula `a` to the given goal.
    pub fn assert(&self, ast: &impl ast::Ast) {
        unsafe { Z3_goal_assert(self.ctx.z3_ctx.0, self.z3_goal, ast.get_z3_ast()) }
    }

    /// Return true if the given goal contains the formula `false`.
    pub fn is_inconsistent(&self) -> bool {
        unsafe { Z3_goal_inconsistent(self.ctx.z3_ctx.0, self.z3_goal) }
    }

    /// Return the depth of the given goal. It tracks how many transformations were applied to it.
    pub fn get_depth(&self) -> u32 {
        unsafe { Z3_goal_depth(self.ctx.z3_ctx.0, self.z3_goal) }
    }

    /// Return the number of formulas in the given goal.
    pub fn get_size(&self) -> u32 {
        unsafe { Z3_goal_size(self.ctx.z3_ctx.0, self.z3_goal) }
    }

    /// Return the number of formulas, subformulas and terms in the given goal.
    pub fn get_num_expr(&self) -> u32 {
        unsafe { Z3_goal_num_exprs(self.ctx.z3_ctx.0, self.z3_goal) }
    }

    /// Return true if the goal is empty, and it is precise or the product of a under approximation.
    pub fn is_decided_sat(&self) -> bool {
        unsafe { Z3_goal_is_decided_sat(self.ctx.z3_ctx.0, self.z3_goal) }
    }
    /// Return true if the goal contains false, and it is precise or the product of an over approximation.
    pub fn is_decided_unsat(&self) -> bool {
        unsafe { Z3_goal_is_decided_unsat(self.ctx.z3_ctx.0, self.z3_goal) }
    }

    /// Erase all formulas from the given goal.
    pub fn reset(&self) {
        unsafe { Z3_goal_reset(self.ctx.z3_ctx.0, self.z3_goal) };
    }

    /// Return the "precision" of the given goal. Goals can be transformed using over and under approximations.
    pub fn get_precision(&self) -> GoalPrec {
        unsafe { Z3_goal_precision(self.ctx.z3_ctx.0, self.z3_goal) }
    }

    pub fn iter_formulas<'a, T>(&'a self) -> impl Iterator<Item = T> + 'a
    where
        T: Ast,
    {
        let goal_size = self.get_size() as usize;
        let z3_ctx = self.ctx.z3_ctx.0;
        let z3_goal = self.z3_goal;
        (0..goal_size).map(move |i| {
            let formula = unsafe { Z3_goal_formula(z3_ctx, z3_goal, i as u32).unwrap() };
            unsafe { T::wrap(&self.ctx, formula) }
        })
    }

    /// Return a vector of the formulas from the given goal.
    ///
    /// Though not guaranteed by Z3's type system, goals and subgoals are
    /// conceptually always going to be expressions of the [`Bool`] Sort.
    pub fn get_formulas(&self) -> Vec<Bool> {
        let goal_size = self.get_size() as usize;
        let mut formulas: Vec<Bool> = Vec::with_capacity(goal_size);

        for i in 0..goal_size {
            let formula =
                unsafe { Z3_goal_formula(self.ctx.z3_ctx.0, self.z3_goal, i as u32).unwrap() };
            formulas.push(unsafe { Bool::wrap(&self.ctx, formula) });
        }
        formulas
    }
}

impl fmt::Display for Goal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let p = unsafe { Z3_goal_to_string(self.ctx.z3_ctx.0, self.z3_goal) };
        if p.is_null() {
            return Result::Err(fmt::Error);
        }
        match unsafe { CStr::from_ptr(p) }.to_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Result::Err(fmt::Error),
        }
    }
}

impl fmt::Debug for Goal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl Drop for Goal {
    fn drop(&mut self) {
        unsafe {
            Z3_goal_dec_ref(self.ctx.z3_ctx.0, self.z3_goal);
        };
    }
}

unsafe impl Translate for Goal {
    fn translate(&self, ctx: &Context) -> Goal {
        unsafe {
            Goal::wrap(
                ctx,
                Z3_goal_translate(self.ctx.z3_ctx.0, self.z3_goal, ctx.z3_ctx.0).unwrap(),
            )
        }
    }
}
