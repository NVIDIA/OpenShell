use log::debug;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::fmt;
use std::iter::FusedIterator;

use z3_sys::*;

use crate::solver::Solvable;
use crate::{
    AstVector, Context, Model, Optimize, Params, SatResult, Statistics, Symbol,
    ast::{Ast, Bool, Dynamic},
};

use num::{
    bigint::{BigInt, BigUint, Sign},
    rational::BigRational,
};

impl Optimize {
    unsafe fn wrap(ctx: &Context, z3_opt: Z3_optimize) -> Optimize {
        unsafe {
            Z3_optimize_inc_ref(ctx.z3_ctx.0, z3_opt);
        }
        Optimize {
            ctx: ctx.clone(),
            z3_opt,
        }
    }

    /// Create a new optimize context.
    pub fn new() -> Optimize {
        let ctx = &Context::thread_local();
        unsafe { Self::wrap(ctx, Z3_mk_optimize(ctx.z3_ctx.0).unwrap()) }
    }

    /// Parse an SMT-LIB2 string with assertions, soft constraints and optimization objectives.
    /// Add the parsed constraints and objectives to the optimizer.
    pub fn from_string<T: Into<Vec<u8>>>(&self, source_string: T) {
        let source_cstring = CString::new(source_string).unwrap();
        unsafe {
            Z3_optimize_from_string(self.ctx.z3_ctx.0, self.z3_opt, source_cstring.as_ptr());
        }
    }

    /// Get this optimizers 's context.
    pub fn get_context(&self) -> &Context {
        &self.ctx
    }

    /// Add a hard constraint to the optimization context.
    ///
    /// # See also:
    ///
    /// - [`Optimize::assert_soft()`]
    /// - [`Optimize::maximize()`]
    /// - [`Optimize::minimize()`]
    pub fn assert(&self, ast: &impl Ast) {
        unsafe { Z3_optimize_assert(self.ctx.z3_ctx.0, self.z3_opt, ast.get_z3_ast()) };
    }

    /// Assert a constraint `a` into the solver, and track it (in the
    /// unsat) core using the Boolean constant `p`.
    ///
    /// This API is an alternative to
    /// [`Optimize::check()`]
    /// for extracting unsat cores. Both APIs can be used in the same solver.
    /// The unsat core will contain a combination of the Boolean variables
    /// provided using [`Optimize::assert_and_track()`]
    /// and the Boolean literals provided using
    /// [`Optimize::check()`].
    ///
    /// # See also:
    ///
    /// - [`Optimize::assert()`]
    /// - [`Optimize::assert_soft()`]
    pub fn assert_and_track(&self, ast: &Bool, p: &Bool) {
        debug!("assert_and_track: {ast:?}");
        unsafe {
            Z3_optimize_assert_and_track(self.ctx.z3_ctx.0, self.z3_opt, ast.z3_ast, p.z3_ast)
        };
    }

    /// Assert soft constraint to the optimization context.
    /// Weight is a positive, rational penalty for violating the constraint.
    /// Group is an optional identifier to group soft constraints.
    ///
    /// # See also:
    ///
    /// - [`Optimize::assert()`]
    /// - [`Optimize::maximize()`]
    /// - [`Optimize::minimize()`]
    pub fn assert_soft(&self, ast: &impl Ast, weight: impl Weight, group: Option<Symbol>) {
        let weight_string = weight.to_string();
        let weight_cstring = CString::new(weight_string).unwrap();
        let group = group.map(|g| g.as_z3_symbol());

        unsafe {
            Z3_optimize_assert_soft(
                self.ctx.z3_ctx.0,
                self.z3_opt,
                ast.get_z3_ast(),
                weight_cstring.as_ptr(),
                group,
            )
        };
    }

    /// Add a maximization constraint.
    ///
    /// # See also:
    ///
    /// - [`Optimize::assert()`]
    /// - [`Optimize::minimize()`]
    pub fn maximize(&self, ast: &impl Ast) {
        // https://github.com/Z3Prover/z3/blob/09f911d8a84cd91988e5b96b69485b2a9a2edba3/src/opt/opt_context.cpp#L118-L120
        assert!(matches!(
            ast.get_sort().kind(),
            SortKind::Int | SortKind::Real | SortKind::BV
        ));
        unsafe { Z3_optimize_maximize(self.ctx.z3_ctx.0, self.z3_opt, ast.get_z3_ast()) };
    }

    /// Add a minimization constraint.
    ///
    /// # See also:
    ///
    /// - [`Optimize::assert()`]
    /// - [`Optimize::maximize()`]
    pub fn minimize(&self, ast: &impl Ast) {
        assert!(matches!(
            ast.get_sort().kind(),
            SortKind::Int | SortKind::Real | SortKind::BV
        ));
        unsafe { Z3_optimize_minimize(self.ctx.z3_ctx.0, self.z3_opt, ast.get_z3_ast()) };
    }

    /// Return a subset of the assumptions provided to either the last
    ///
    /// * [`Optimize::check`] call, or
    /// * sequence of [`Optimize::assert_and_track`] calls followed
    ///   by an [`Optimize::check`] call.
    ///
    /// These are the assumptions Z3 used in the unsatisfiability proof.
    /// Assumptions are available in Z3. They are used to extract unsatisfiable
    /// cores.  They may be also used to "retract" assumptions. Note that,
    /// assumptions are not really "soft constraints", but they can be used to
    /// implement them.
    ///
    /// By default, the unsat core will not be minimized. Generation of a minimized
    /// unsat core can be enabled via the `"sat.core.minimize"` and `"smt.core.minimize"`
    /// settings for SAT and SMT cores respectively. Generation of minimized unsat cores
    /// will be more expensive.
    ///
    /// # See also:
    ///
    /// - [`Optimize::check`]
    pub fn get_unsat_core(&self) -> Vec<Bool> {
        let Some(raw) = (unsafe { Z3_optimize_get_unsat_core(self.ctx.z3_ctx.0, self.z3_opt) })
        else {
            return vec![];
        };
        let av = unsafe { AstVector::wrap(&self.ctx, raw) };
        av.try_into().expect("unsat core contains only Bool")
    }

    /// Create a backtracking point.
    ///
    /// The optimize solver contains a set of rules, added facts and assertions.
    /// The set of rules, facts and assertions are restored upon calling
    /// [`Optimize::pop()`].
    ///
    /// # See also:
    ///
    /// - [`Optimize::pop()`]
    pub fn push(&self) {
        unsafe { Z3_optimize_push(self.ctx.z3_ctx.0, self.z3_opt) };
    }

    /// Backtrack one level.
    ///
    /// # Preconditions:
    ///
    /// - The number of calls to [`Optimize::pop`] cannot exceed the number of calls to
    ///   [`Optimize::push()`].
    ///
    /// # See also:
    ///
    /// - [`Optimize::push()`]
    pub fn pop(&self) {
        unsafe { Z3_optimize_pop(self.ctx.z3_ctx.0, self.z3_opt) };
    }

    /// Check consistency and produce optimal values.
    ///
    /// # See also:
    ///
    /// - [`Optimize::get_model()`]
    pub fn check(&self, assumptions: &[Bool]) -> SatResult {
        let assumptions: Vec<Z3_ast> = assumptions.iter().map(|a| a.z3_ast).collect();
        match unsafe {
            Z3_optimize_check(
                self.ctx.z3_ctx.0,
                self.z3_opt,
                assumptions.len().try_into().unwrap(),
                assumptions.as_ptr(),
            )
        } {
            Z3_L_FALSE => SatResult::Unsat,
            Z3_L_UNDEF => SatResult::Unknown,
            Z3_L_TRUE => SatResult::Sat,
            _ => unreachable!(),
        }
    }

    /// Retrieve the model for the last [`Optimize::check()`].
    ///
    /// The error handler is invoked if a model is not available because
    /// the commands above were not invoked for the given optimization
    /// solver, or if the result was [`SatResult::Unsat`].
    pub fn get_model(&self) -> Option<Model> {
        Model::of_optimize(self)
    }

    /// Retrieve the objectives for the last [`Optimize::check()`].
    ///
    /// This contains maximize/minimize objectives and grouped soft constraints.
    pub fn get_objectives(&self) -> Vec<Dynamic> {
        let raw = unsafe { Z3_optimize_get_objectives(self.ctx.z3_ctx.0, self.z3_opt).unwrap() };
        unsafe { AstVector::wrap(&self.ctx, raw) }.to_vec()
    }

    /// Retrieve a string that describes the last status returned by [`Optimize::check()`].
    ///
    /// Use this method when [`Optimize::check()`] returns [`SatResult::Unknown`].
    pub fn get_reason_unknown(&self) -> Option<String> {
        let p = unsafe { Z3_optimize_get_reason_unknown(self.ctx.z3_ctx.0, self.z3_opt) };
        if p.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(p) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }

    /// Configure the parameters for this Optimize.
    pub fn set_params(&self, params: &Params) {
        unsafe { Z3_optimize_set_params(self.ctx.z3_ctx.0, self.z3_opt, params.z3_params) };
    }

    /// Retrieve the statistics for the last [`Optimize::check()`].
    pub fn get_statistics(&self) -> Statistics {
        unsafe {
            Statistics::wrap(
                &self.ctx,
                Z3_optimize_get_statistics(self.ctx.z3_ctx.0, self.z3_opt).unwrap(),
            )
        }
    }

    /// Consume this [`Optimize`] and iterate over solutions to the given [`Solvable`].
    ///
    /// Each iteration calls [`Optimize::check`] with no assumptions and asserts a
    /// counterexample constraint to exclude the current solution, yielding all
    /// distinct model instances until the optimizer returns `UNSAT` or `UNKNOWN`.
    ///
    /// # See also
    ///
    /// - [`Optimize::check_and_get_model`]
    pub fn into_solutions<T: Solvable>(
        self,
        t: T,
        model_completion: bool,
    ) -> impl FusedIterator<Item = T::ModelInstance> {
        OptimizeIterator {
            optimize: self,
            ast: t,
            model_completion,
        }
        .fuse()
    }

    /// Check the optimizer and, if satisfiable, return a single model instance for `t`.
    ///
    /// Combines `check(&[])` + `get_model()` + `Solvable::read_from_model`.
    /// Returns `Some(instance)` on `Sat` with successful model extraction; `None` otherwise.
    ///
    /// # See also
    ///
    /// - [`Optimize::into_solutions`]
    pub fn check_and_get_model<T: Solvable>(
        &self,
        t: T,
        model_completion: bool,
    ) -> Option<T::ModelInstance> {
        match self.check(&[]) {
            SatResult::Sat => {
                let model = self.get_model()?;
                t.read_from_model(&model, model_completion)
            }
            _ => None,
        }
    }

    /// Return all assertions currently in the optimizer.
    pub fn get_assertions(&self) -> Vec<Bool> {
        let av = unsafe {
            AstVector::wrap(
                &self.ctx,
                Z3_optimize_get_assertions(self.ctx.z3_ctx.0, self.z3_opt).unwrap(),
            )
        };
        av.try_into().expect("solver assertions are always Bool")
    }
}

struct OptimizeIterator<T> {
    optimize: Optimize,
    ast: T,
    model_completion: bool,
}

impl<T: Solvable> Iterator for OptimizeIterator<T> {
    type Item = T::ModelInstance;

    fn next(&mut self) -> Option<Self::Item> {
        match self.optimize.check(&[]) {
            SatResult::Sat => {
                let model = self.optimize.get_model()?;
                let instance = self.ast.read_from_model(&model, self.model_completion)?;
                let counterexample = self.ast.generate_constraint(&instance);
                self.optimize.assert(&counterexample);
                Some(instance)
            }
            _ => None,
        }
    }
}

impl Default for Optimize {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Optimize {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let p = unsafe { Z3_optimize_to_string(self.ctx.z3_ctx.0, self.z3_opt) };
        if p.is_null() {
            return Result::Err(fmt::Error);
        }
        match unsafe { CStr::from_ptr(p) }.to_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Result::Err(fmt::Error),
        }
    }
}

impl fmt::Debug for Optimize {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl Drop for Optimize {
    fn drop(&mut self) {
        unsafe { Z3_optimize_dec_ref(self.ctx.z3_ctx.0, self.z3_opt) };
    }
}

/// A rational non-negative weight for soft assertions.
/// This trait is sealed and cannot be implemented for types outside of
/// `z3`.
///
/// # See also:
///
/// - [`Optimize::assert_soft()`]
pub trait Weight: private::Sealed {
    /// This is purposefully distinct from `ToString` to allow
    /// specifying a `to_string` for tuples.
    fn to_string(&self) -> String;
}

macro_rules! impl_weight {
    ($($ty: ty),*) => {
        $(
            impl Weight for $ty {
                fn to_string(&self) -> String {
                    ToString::to_string(&self)
                }
            }

            impl Weight for ($ty, $ty) {
                fn to_string(&self) -> String {
                    format!("{} / {}", self.0, self.1)
                }
            }
        )*
    };
}

impl_weight! {
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
}

impl Weight for BigInt {
    fn to_string(&self) -> String {
        assert_ne!(self.sign(), Sign::Minus);
        self.to_str_radix(10)
    }
}

impl Weight for BigUint {
    fn to_string(&self) -> String {
        self.to_str_radix(10)
    }
}

impl Weight for BigRational {
    fn to_string(&self) -> String {
        assert_ne!(self.numer().sign(), Sign::Minus);
        assert_ne!(self.denom().sign(), Sign::Minus);
        format!(
            "{} / {}",
            self.numer().to_str_radix(10),
            self.denom().to_str_radix(10)
        )
    }
}

macro_rules! impl_sealed {
    ($($ty: ty),*) => {
        mod private {
            #[allow(unused_imports)]
            use super::*;
            pub trait Sealed {}
            $(
                impl Sealed for $ty {}
                impl Sealed for ($ty, $ty) {}
            )*

            impl Sealed for BigInt {}
            impl Sealed for BigUint {}
            impl Sealed for BigRational {}
        }
    };
}

impl_sealed! {
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
}
