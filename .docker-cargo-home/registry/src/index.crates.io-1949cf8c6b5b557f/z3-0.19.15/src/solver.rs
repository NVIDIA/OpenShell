use log::debug;
use std::borrow::Borrow;
use std::ffi::{CStr, CString};
use std::fmt;
use std::iter::FusedIterator;
use z3_sys::*;

use crate::ast::Bool;
use crate::{
    AstVector, Context, Model, Params, SatResult, Solver, Statistics, Symbol, Translate, ast,
    ast::Ast,
};
use std::ops::AddAssign;

impl Solver {
    pub(crate) unsafe fn wrap(ctx: &Context, z3_slv: Z3_solver) -> Solver {
        unsafe {
            Z3_solver_inc_ref(ctx.z3_ctx.0, z3_slv);
        }
        Solver {
            ctx: ctx.clone(),
            z3_slv,
        }
    }

    /// Create a new solver. This solver is a "combined solver"
    /// that internally uses a non-incremental (`solver1`) and an
    /// incremental solver (`solver2`). This combined solver changes
    /// its behaviour based on how it is used and how its parameters are set.
    ///
    /// If the solver is used in a non incremental way (i.e. no calls to
    /// [`Solver::push()`] or [`Solver::pop()`], and no calls to
    /// [`Solver::assert()`] or [`Solver::assert_and_track()`] after checking
    /// satisfiability without an intervening [`Solver::reset()`]) then `solver1`
    /// will be used. This solver will apply Z3's "default" tactic.
    ///
    /// The "default" tactic will attempt to probe the logic used by the
    /// assertions and will apply a specialized tactic if one is supported.
    /// Otherwise the general `(and-then simplify smt)` tactic will be used.
    ///
    /// If the solver is used in an incremental way then the combined solver
    /// will switch to using `solver2` (which behaves similarly to the general
    /// "smt" tactic).
    ///
    /// Note however it is possible to set the `solver2_timeout`,
    /// `solver2_unknown`, and `ignore_solver1` parameters of the combined
    /// solver to change its behaviour.
    pub fn new() -> Solver {
        let ctx = &Context::thread_local();
        unsafe { Self::wrap(ctx, Z3_mk_solver(ctx.z3_ctx.0).unwrap()) }
    }

    /// Parse an SMT-LIB2 string with assertions, soft constraints and optimization objectives.
    /// Add the parsed constraints and objectives to the solver.
    pub fn from_string<T: Into<Vec<u8>>>(&self, source_string: T) {
        let source_cstring = CString::new(source_string).unwrap();
        unsafe {
            Z3_solver_from_string(self.ctx.z3_ctx.0, self.z3_slv, source_cstring.as_ptr());
        }
    }

    /// Create a new solver customized for the given logic.
    /// It returns `None` if the logic is unknown or unsupported.
    pub fn new_for_logic<S: Into<Symbol>>(logic: S) -> Option<Solver> {
        let ctx = &Context::thread_local();
        unsafe {
            let s = Z3_mk_solver_for_logic(ctx.z3_ctx.0, logic.into().as_z3_symbol())?;
            Some(Self::wrap(ctx, s))
        }
    }

    /// Get this solver's context.
    pub fn get_context(&self) -> &Context {
        &self.ctx
    }

    /// Assert a constraint into the solver.
    ///
    /// The functions [`Solver::check()`] and [`Solver::check_assumptions()`]
    /// should be used to check whether the logical context is consistent
    /// or not.
    ///
    /// ```rust
    /// # use z3::{Config, Context, Solver, ast, SatResult, ast::Bool};
    /// let mut solver = Solver::new();
    ///
    /// solver.assert(&Bool::from_bool(true));
    /// solver += &Bool::from_bool(false);
    /// solver += Bool::fresh_const("");
    ///
    /// assert_eq!(solver.check(), SatResult::Unsat);
    /// ````
    ///
    /// # See also:
    ///
    /// - [`Solver::assert_and_track()`]
    pub fn assert<T: Borrow<Bool>>(&self, ast: T) {
        let ast = ast.borrow();
        debug!("assert: {ast:?}");
        unsafe { Z3_solver_assert(self.ctx.z3_ctx.0, self.z3_slv, ast.z3_ast) };
    }

    /// Assert a constraint `a` into the solver, and track it (in the
    /// unsat) core using the Boolean constant `p`.
    ///
    /// This API is an alternative to
    /// [`Solver::check_assumptions()`]
    /// for extracting unsat cores. Both APIs can be used in the same solver.
    /// The unsat core will contain a combination of the Boolean variables
    /// provided using [`Solver::assert_and_track()`]
    /// and the Boolean literals provided using
    /// [`Solver::check_assumptions()`].
    ///
    /// # See also:
    ///
    /// - [`Solver::assert()`]
    pub fn assert_and_track<T: Into<Bool>>(&self, ast: T, p: &Bool) {
        let ast = ast.into();
        debug!("assert_and_track: {ast:?}");
        unsafe { Z3_solver_assert_and_track(self.ctx.z3_ctx.0, self.z3_slv, ast.z3_ast, p.z3_ast) };
    }

    /// Remove all assertions from the solver.
    pub fn reset(&self) {
        unsafe { Z3_solver_reset(self.ctx.z3_ctx.0, self.z3_slv) };
    }

    /// Check whether the assertions in a given solver are consistent or not.
    ///
    /// The function [`Solver::get_model()`]
    /// retrieves a model if the assertions is satisfiable (i.e., the
    /// result is [`SatResult::Sat`]) and [model construction is enabled].
    /// Note that if the call returns `SatResult::Unknown`, Z3 does not
    /// ensure that calls to [`Solver::get_model()`]
    /// succeed and any models produced in this case are not guaranteed
    /// to satisfy the assertions.
    ///
    /// The function [`Solver::get_proof()`]
    /// retrieves a proof if [proof generation was enabled] when the context
    /// was created, and the assertions are unsatisfiable (i.e., the result
    /// is [`SatResult::Unsat`]).
    ///
    /// # See also:
    ///
    /// - [`Config::set_model_generation()`](crate::Config::set_model_generation)
    /// - [`Config::set_proof_generation()`](crate::Config::set_proof_generation)
    /// - [`Solver::check_assumptions()`]
    ///
    /// [model construction is enabled]: crate::Config::set_model_generation
    /// [proof generation was enabled]: crate::Config::set_proof_generation
    pub fn check(&self) -> SatResult {
        match unsafe { Z3_solver_check(self.ctx.z3_ctx.0, self.z3_slv) } {
            Z3_L_FALSE => SatResult::Unsat,
            Z3_L_UNDEF => SatResult::Unknown,
            Z3_L_TRUE => SatResult::Sat,
            _ => unreachable!(),
        }
    }

    /// Check whether the assertions in the given solver and
    /// optional assumptions are consistent or not.
    ///
    /// The function [`Solver::get_unsat_core()`]
    /// retrieves the subset of the assumptions used in the
    /// unsatisfiability proof produced by Z3.
    ///
    /// # See also:
    ///
    /// - [`Solver::check()`]
    pub fn check_assumptions(&self, assumptions: &[Bool]) -> SatResult {
        let a: Vec<Z3_ast> = assumptions.iter().map(|a| a.z3_ast).collect();
        match unsafe {
            Z3_solver_check_assumptions(self.ctx.z3_ctx.0, self.z3_slv, a.len() as u32, a.as_ptr())
        } {
            Z3_L_FALSE => SatResult::Unsat,
            Z3_L_UNDEF => SatResult::Unknown,
            Z3_L_TRUE => SatResult::Sat,
            _ => unreachable!(),
        }
    }

    /// Return all assertions currently in the solver.
    pub fn get_assertions(&self) -> Vec<Bool> {
        let av = unsafe {
            AstVector::wrap(
                &self.ctx,
                Z3_solver_get_assertions(self.ctx.z3_ctx.0, self.z3_slv).unwrap(),
            )
        };
        av.try_into().expect("solver assertions are always Bool")
    }

    /// Return a subset of the assumptions provided to either the last
    ///
    /// * [`Solver::check_assumptions`] call, or
    /// * sequence of [`Solver::assert_and_track`] calls followed
    ///   by a [`Solver::check`] call.
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
    /// - [`Solver::check_assumptions`]
    /// - [`Solver::assert_and_track`]
    pub fn get_unsat_core(&self) -> Vec<Bool> {
        let Some(raw) = (unsafe { Z3_solver_get_unsat_core(self.ctx.z3_ctx.0, self.z3_slv) })
        else {
            return vec![];
        };
        let av = unsafe { AstVector::wrap(&self.ctx, raw) };
        av.try_into().expect("unsat core contains only Bool")
    }

    /// Retrieve consequences from the solver given a set of assumptions.
    pub fn get_consequences(&self, assumptions: &[Bool], variables: &[Bool]) -> Vec<Bool> {
        let assumptions_vec = AstVector::from(assumptions);
        let variables_vec = AstVector::from(variables);
        let consequences_vec = AstVector::new();

        unsafe {
            Z3_solver_get_consequences(
                self.ctx.z3_ctx.0,
                self.z3_slv,
                assumptions_vec.z3_ast_vector,
                variables_vec.z3_ast_vector,
                consequences_vec.z3_ast_vector,
            );
        }

        consequences_vec
            .try_into()
            .expect("consequences are always Bool")
    }

    /// Create a backtracking point.
    ///
    /// The solver contains a stack of assertions.
    ///
    /// # See also:
    ///
    /// - [`Solver::pop()`]
    pub fn push(&self) {
        unsafe { Z3_solver_push(self.ctx.z3_ctx.0, self.z3_slv) };
    }

    /// Backtrack `n` backtracking points.
    ///
    /// # See also:
    ///
    /// - [`Solver::push()`]
    pub fn pop(&self, n: u32) {
        unsafe { Z3_solver_pop(self.ctx.z3_ctx.0, self.z3_slv, n) };
    }

    /// Retrieve the model for the last [`Solver::check()`]
    /// or [`Solver::check_assumptions()`] if the
    /// assertions is satisfiable (i.e., the result is
    /// `SatResult::Sat`) and [model construction is enabled].
    ///
    /// It can also be used
    /// if the result is `SatResult::Unknown`, but the returned model
    /// is not guaranteed to satisfy quantified assertions.
    ///
    /// The error handler is invoked if a model is not available because
    /// the commands above were not invoked for the given solver, or if
    /// the result was [`SatResult::Unsat`].
    ///
    /// [model construction is enabled]: crate::Config::set_model_generation
    pub fn get_model(&self) -> Option<Model> {
        Model::of_solver(self)
    }

    /// Retrieve the proof for the last [`Solver::check()`]
    /// or [`Solver::check_assumptions()`].
    ///
    /// The error handler is invoked if [proof generation is not enabled],
    /// or if the commands above were not invoked for the given solver,
    /// or if the result was different from [`SatResult::Unsat`].
    ///
    /// # See also:
    ///
    /// - [`Config::set_proof_generation()`](crate::Config::set_proof_generation)
    ///
    /// [proof generation is not enabled]: crate::Config::set_proof_generation
    //
    // This seems to actually return an Ast with kind `SortKind::Unknown`, which we don't
    // have an Ast subtype for yet.
    pub fn get_proof(&self) -> Option<impl Ast> {
        let m = unsafe { Z3_solver_get_proof(self.ctx.z3_ctx.0, self.z3_slv) }?;
        Some(unsafe { ast::Dynamic::wrap(&self.ctx, m) })
    }

    /// Return a brief justification for an "unknown" result (i.e.,
    /// [`SatResult::Unknown`]) for the commands [`Solver::check()`]
    /// and [`Solver::check_assumptions()`].
    pub fn get_reason_unknown(&self) -> Option<String> {
        let p = unsafe { Z3_solver_get_reason_unknown(self.ctx.z3_ctx.0, self.z3_slv) };
        if p.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(p) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }

    /// Set the current solver using the given parameters.
    pub fn set_params(&self, params: &Params) {
        unsafe { Z3_solver_set_params(self.ctx.z3_ctx.0, self.z3_slv, params.z3_params) };
    }

    /// Retrieve the statistics for the last [`Solver::check()`].
    pub fn get_statistics(&self) -> Statistics {
        unsafe {
            Statistics::wrap(
                &self.ctx,
                Z3_solver_get_statistics(self.ctx.z3_ctx.0, self.z3_slv).unwrap(),
            )
        }
    }

    pub fn to_smt2(&self) -> String {
        let name = CString::new("benchmark generated from rust API").unwrap();
        let logic = CString::new("").unwrap();
        let status = CString::new("unknown").unwrap();
        let attributes = CString::new("").unwrap();
        let assumptions = self.get_assertions();
        let mut num_assumptions = assumptions.len() as u32;
        let formula = if num_assumptions > 0 {
            num_assumptions -= 1;
            assumptions[num_assumptions as usize].z3_ast
        } else {
            Bool::from_bool(true).z3_ast
        };
        let z3_assumptions = assumptions.iter().map(|a| a.z3_ast).collect::<Vec<_>>();

        let p = unsafe {
            Z3_benchmark_to_smtlib_string(
                self.ctx.z3_ctx.0,
                name.as_ptr(),
                logic.as_ptr(),
                status.as_ptr(),
                attributes.as_ptr(),
                num_assumptions,
                z3_assumptions.as_ptr(),
                formula,
            )
        };
        if p.is_null() {
            return String::new();
        }
        unsafe { CStr::from_ptr(p) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
            .unwrap_or_else(String::new)
    }

    /// Iterates over models for the given [`Solvable`] from the current state of a [`Solver`].
    ///
    /// The iterator terminates if the [`Solver`] returns `UNSAT` or `UNKNOWN`, as well as if model
    /// generation fails. This iterator may also _never_ terminate as some problems have infinite
    /// solutions. It is recommended to use [`Iterator::take`] if your problem has an unbounded number
    /// of solutions.
    ///
    /// Note that, since this iterator is querying the solver, it's not guaranteed to be at all "fast":
    /// every iteration requires querying the solver and constructing a model, which can take time. This
    /// interface is merely here as a clean alternative to manually issuing [`Solver::check`] and [`Solver::get_model`]
    /// calls.
    ///
    /// The [`Solver`] given to this method is [`Clone`]'d when producing the iterator: no change
    /// is made in the solver passed to the function.
    ///
    /// # Examples
    ///
    /// This can be used to iterate over solutions to individual [`Ast`]s:
    ///
    /// ```
    /// # use z3::Solver;
    /// # use z3::ast::*;
    ///  let s = Solver::new();
    ///  let a = Int::new_const("a");
    ///  s.assert(a.le(4));
    ///  s.assert(a.ge(0));
    ///  let solutions: Vec<_> = s.solutions(a, true).collect();
    ///  let mut solutions: Vec<_> = solutions.into_iter().map(|a|a.as_u64().unwrap()).collect();
    ///  solutions.sort();
    ///  assert_eq!(vec![0,1,2,3,4], solutions);
    /// ```
    ///
    /// As well as solutions to multiple [`Ast`]s, if passed through a [`Vec`], an [`array`] or a [`slice`]:
    ///
    /// ```
    /// # use z3::Solver;
    /// # use z3::ast::*;
    ///  let s = Solver::new();
    ///  let a = Int::new_const("a");
    ///  s.assert(a.le(2));
    ///  s.assert(a.ge(0));
    ///  let solutions: Vec<_> = s.solutions(&[a.clone(), a+2], true).collect();
    ///  // Doing all this to avoid relying on the order Z3 returns solutions.
    ///  let mut solutions: Vec<Vec<_>> = solutions.into_iter().map(|a|a.into_iter().map(|b|b.as_u64().unwrap()).collect()).collect();
    ///  solutions.sort_by(|a,b| a[0].cmp(&b[0]));
    ///
    ///  assert_eq!(vec![vec![0,2], vec![1,3], vec![2,4]], solutions);
    /// ```
    ///
    /// It is also possible to pass in differing types of [`Ast`]s in a [`tuple`]. The traits to allow
    /// this have been implemented for [`tuple`]s of arity 2 and 3. If you need more, it is suggested
    /// to use a struct (see the next example):
    ///
    /// ```
    /// # use z3::Solver;
    /// # use z3::ast::*;
    ///  let s = Solver::new();
    ///  let a = Int::new_const("a");
    ///  let b = BV::new_const("b", 8);
    ///  s.assert(a.lt(1));
    ///  s.assert(a.ge(0));
    ///  s.assert(b.bvxor(0xff).to_int(false).eq(&a));
    ///  let solutions: Vec<_> = s.solutions((a, b), true).collect();
    ///  assert_eq!(solutions.len(), 1);
    ///  let solution = &solutions[0];
    ///  assert_eq!(solution.0, 0);
    ///  assert_eq!(solution.1, 0xff);
    /// ```
    ///
    /// Users can also implement [`Solvable`] on their types that wrap Z3 types to allow
    /// iterating over their models with this API:
    ///
    /// ```
    /// # use z3::ast::*;
    /// # use z3::*;
    /// #[derive(Clone)]
    ///  struct MyStruct{
    ///    pub a: Int,
    ///    pub b: Int
    ///  }
    ///
    ///  impl Solvable for MyStruct {
    ///     type ModelInstance = Self;
    ///     fn read_from_model(&self, model: &Model, model_completion: bool) -> Option<Self> {
    ///         Some(
    ///             Self{
    ///                 a: model.eval(&self.a, model_completion).unwrap(),
    ///                 b: model.eval(&self.b, model_completion).unwrap()
    ///             }
    ///         )
    ///     }
    ///
    ///     fn generate_constraint(&self, model: &Self) -> Bool {
    ///         Bool::or(&[self.a.eq(&model.a).not(), self.b.eq(&model.b).not()])
    ///     }
    ///  }
    ///
    ///  let s = Solver::new();
    ///  let my_struct = MyStruct{
    ///     a: Int::fresh_const("a"),
    ///     b: Int::fresh_const("b")
    ///  };
    ///  // only valid model will be a = 0 and b = 4
    ///  s.assert(my_struct.a.lt(1));
    ///  s.assert(my_struct.a.ge(0));
    ///  s.assert(my_struct.b.eq(&my_struct.a + 4));
    ///
    ///  let solutions: Vec<_> = s.solutions(&my_struct, true).collect();
    ///  assert_eq!(solutions.len(), 1);
    ///  assert_eq!(solutions[0].a, 0);
    ///  assert_eq!(solutions[0].b, 4);
    /// ```
    pub fn solutions<T: Solvable>(
        &self,
        t: T,
        model_completion: bool,
    ) -> impl FusedIterator<Item = T::ModelInstance> {
        SolverIterator {
            solver: self.clone(),
            ast: t,
            model_completion,
        }
        .fuse()
    }

    /// Consume the current [`Solver`] and iterate over solutions to the given [`Solvable`].
    ///
    /// # Example
    ///
    /// ```
    /// # use z3::Solver;
    /// # use z3::ast::*;
    ///  let s = Solver::new_for_logic("QF_BV").unwrap();
    ///  let a = BV::new_const("a", 8);
    ///  let b = BV::new_const("b", 8);
    ///  s.assert(a.bvxor(0xff).eq(&b));
    ///  s.assert(b.eq(0x25));
    ///  let solutions: Vec<_> = s.into_solutions([a,b], true).collect();
    ///  assert_eq!(solutions.len(), 1);
    ///  let solution = &solutions[0];
    ///  assert_eq!(solution[0], 0xda);
    ///  assert_eq!(solution[1], 0x25);
    ///```
    /// # See also:
    ///
    /// - [`Solver::solutions`]
    pub fn into_solutions<T: Solvable>(
        self,
        t: T,
        model_completion: bool,
    ) -> impl FusedIterator<Item = T::ModelInstance> {
        SolverIterator {
            solver: self,
            ast: t,
            model_completion,
        }
        .fuse()
    }

    /// Check the solver and, if satisfiable, return a single model instance for `t`.
    ///
    /// This is a convenience that combines `check()` + `get_model()` + `Solvable::read_from_model`.
    /// If the check returns `SatResult::Sat` and model construction and extraction succeed, this
    /// method returns `Some(instance)`. For any other result (`Unsat`, `Unknown`) or if model
    /// construction/reading fails, it returns `None`.
    ///
    /// # Example
    ///
    /// ```
    /// # use z3::Solver;
    /// # use z3::ast::*;
    ///  let s = Solver::new();
    ///  let a = Int::new_const("a");
    ///  s.assert(a.ge(0));
    ///  s.assert(a.le(2));
    ///  let concrete_a = s.check_and_get_model(a, true).unwrap();
    ///  // `concrete_a` is an `Int` value extracted from the model
    ///  let val = concrete_a.as_u64().unwrap();
    ///  assert!(val <= 2);
    /// ```
    pub fn check_and_get_model<T: Solvable>(
        &self,
        t: T,
        model_completion: bool,
    ) -> Option<T::ModelInstance> {
        match self.check() {
            SatResult::Sat => {
                let model = self.get_model()?;
                let instance = t.read_from_model(&model, model_completion)?;
                Some(instance)
            }
            _ => None,
        }
    }
}

impl Default for Solver {
    fn default() -> Self {
        Self::new()
    }
}

struct SolverIterator<T> {
    solver: Solver,
    ast: T,
    model_completion: bool,
}

impl<T: Solvable> Iterator for SolverIterator<T> {
    type Item = T::ModelInstance;

    fn next(&mut self) -> Option<Self::Item> {
        match self.solver.check() {
            SatResult::Sat => {
                let model = self.solver.get_model()?;
                let instance = self.ast.read_from_model(&model, self.model_completion)?;
                let counterexample = self.ast.generate_constraint(&instance);
                self.solver.assert(counterexample);
                Some(instance)
            }
            _ => None,
        }
    }
}

impl fmt::Display for Solver {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let p = unsafe { Z3_solver_to_string(self.ctx.z3_ctx.0, self.z3_slv) };
        if p.is_null() {
            return Result::Err(fmt::Error);
        }
        match unsafe { CStr::from_ptr(p) }.to_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Result::Err(fmt::Error),
        }
    }
}

impl fmt::Debug for Solver {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl Drop for Solver {
    fn drop(&mut self) {
        unsafe { Z3_solver_dec_ref(self.ctx.z3_ctx.0, self.z3_slv) };
    }
}

/// Creates a new [`Solver`] with the same assertions, tactics, and parameters
/// as the original
impl Clone for Solver {
    fn clone(self: &Solver) -> Self {
        self.translate(&Context::thread_local())
    }
}

unsafe impl Translate for Solver {
    fn translate(&self, dest: &Context) -> Solver {
        unsafe {
            Solver::wrap(
                dest,
                Z3_solver_translate(self.ctx.z3_ctx.0, self.z3_slv, dest.z3_ctx.0).unwrap(),
            )
        }
    }
}

impl AddAssign<&Bool> for Solver {
    fn add_assign(&mut self, rhs: &Bool) {
        self.assert(rhs);
    }
}

impl AddAssign<Bool> for Solver {
    fn add_assign(&mut self, rhs: Bool) {
        self.assert(&rhs);
    }
}

/// Indicates that a type can be evaluated from a [`Model`] and produce a [`Bool`] counterexample,
/// allowing usage in the [`Solver::solutions`] iterator pattern.
///
/// Specifically, types implementing this trait:
/// * Can read a Z3 [`Model`] in a structured way to produce an instance
///   of the type with its inner [`Ast`]s constrained by the [`Model`]
/// * Can generate a counter-example assertion from its internal [`Ast`]s
///   to constrain a [`Solver`] (usually just a disjunction of "not-equal"s)
pub trait Solvable: Sized + Clone {
    /// The type to be extracted from the [`Solver`]'s Model.
    ///
    /// It will usually just be [`Self`] and must be [`Solvable`]. This is only an associated
    /// type and not just hard-coded to [`Self`] to allow for passing both owned and borrowed
    /// values into [`Solver::solutions`], and to allow implementing this trait for types like
    /// `&[T]`.
    type ModelInstance: Solvable;

    /// Defines how to derive data derived from the implementing type (usually just a [`Self`])
    /// and a given [`Model`].
    ///
    /// Usually this just invokes [`Model::eval`] on some [`Ast`]s and wraps
    /// it up into the proper type.
    fn read_from_model(&self, model: &Model, model_completion: bool)
    -> Option<Self::ModelInstance>;

    /// Produce a [`Bool`] assertion ruling out the given model from the valuation of `self`.
    ///
    /// This is used to advance the [`Solver`] in [`Solver::solutions`]. This is usually just a
    /// disjunction (in case of multiple terms) of "not equal" assertions between `self` and `model`.
    fn generate_constraint(&self, model: &Self::ModelInstance) -> Bool;
}

impl<T: Solvable> Solvable for &T {
    type ModelInstance = T::ModelInstance;
    fn read_from_model(
        &self,
        model: &Model,
        model_completion: bool,
    ) -> Option<Self::ModelInstance> {
        (*self).read_from_model(model, model_completion)
    }

    fn generate_constraint(&self, model: &Self::ModelInstance) -> Bool {
        (*self).generate_constraint(model)
    }
}

impl<T: Solvable> Solvable for Vec<T> {
    type ModelInstance = Vec<T::ModelInstance>;
    fn read_from_model(
        &self,
        model: &Model,
        model_completion: bool,
    ) -> Option<Self::ModelInstance> {
        self.iter()
            .map(|x| x.read_from_model(model, model_completion))
            .collect()
    }

    fn generate_constraint(&self, model: &Self::ModelInstance) -> Bool {
        let bools: Vec<_> = self
            .iter()
            .zip(model)
            .map(|(a, b)| a.generate_constraint(b))
            .collect();
        Bool::or(&bools)
    }
}

impl<T: Solvable> Solvable for &[T] {
    type ModelInstance = Vec<T::ModelInstance>;
    fn read_from_model(
        &self,
        model: &Model,
        model_completion: bool,
    ) -> Option<Self::ModelInstance> {
        self.iter()
            .map(|x| x.read_from_model(model, model_completion))
            .collect()
    }

    fn generate_constraint(&self, model: &Self::ModelInstance) -> Bool {
        let bools: Vec<_> = self
            .iter()
            .zip(model)
            .map(|(a, b)| a.generate_constraint(b))
            .collect();
        Bool::or(&bools)
    }
}

impl<T: Solvable + Clone, const N: usize> Solvable for [T; N] {
    type ModelInstance = [T::ModelInstance; N];
    fn read_from_model(
        &self,
        model: &Model,
        model_completion: bool,
    ) -> Option<Self::ModelInstance> {
        let v: Option<Vec<_>> = self
            .iter()
            .map(|x| x.read_from_model(model, model_completion))
            .collect();
        let v = v?;
        let a: [T::ModelInstance; N] = v.try_into().ok()?;
        Some(a)
    }

    fn generate_constraint(&self, model: &Self::ModelInstance) -> Bool {
        let bools: Vec<_> = self
            .iter()
            .zip(model)
            .map(|(a, b)| a.generate_constraint(b))
            .collect();
        Bool::or(&bools)
    }
}
impl<A: Solvable, B: Solvable> Solvable for (A, B) {
    type ModelInstance = (A::ModelInstance, B::ModelInstance);
    fn read_from_model(
        &self,
        model: &Model,
        model_completion: bool,
    ) -> Option<Self::ModelInstance> {
        let (a, b) = self;
        Some((
            a.read_from_model(model, model_completion)?,
            b.read_from_model(model, model_completion)?,
        ))
    }

    fn generate_constraint(&self, model: &Self::ModelInstance) -> Bool {
        let (a1, b1) = self;
        let (a2, b2) = model;
        Bool::or(&[a1.generate_constraint(a2), b1.generate_constraint(b2)])
    }
}

impl<A: Solvable, B: Solvable, C: Solvable> Solvable for (A, B, C) {
    type ModelInstance = (A::ModelInstance, B::ModelInstance, C::ModelInstance);
    fn read_from_model(
        &self,
        model: &Model,
        model_completion: bool,
    ) -> Option<Self::ModelInstance> {
        let (a, b, c) = self;
        Some((
            a.read_from_model(model, model_completion)?,
            b.read_from_model(model, model_completion)?,
            c.read_from_model(model, model_completion)?,
        ))
    }

    fn generate_constraint(&self, model: &Self::ModelInstance) -> Bool {
        let (a1, b1, c1) = self;
        let (a2, b2, c2) = model;
        Bool::or(&[
            a1.generate_constraint(a2),
            b1.generate_constraint(b2),
            c1.generate_constraint(c2),
        ])
    }
}

// todo: there may be a way to do this with a macro, but I can't figure it out, without needing
// to bring in the `paste` crate. Since this is niche anyway, I'm just going to do these two and
// we can add more later if needed.
