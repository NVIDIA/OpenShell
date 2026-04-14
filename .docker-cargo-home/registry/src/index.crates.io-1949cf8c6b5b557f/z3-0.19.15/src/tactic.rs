use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::c_uint;
use std::result::Result;
use std::str::Utf8Error;
use std::time::Duration;
use z3_sys::*;

use crate::{ApplyResult, Context, Goal, Params, Probe, Solver, Tactic};

impl ApplyResult {
    unsafe fn wrap(ctx: &Context, z3_apply_result: Z3_apply_result) -> ApplyResult {
        unsafe {
            Z3_apply_result_inc_ref(ctx.z3_ctx.0, z3_apply_result);
        }
        ApplyResult {
            ctx: ctx.clone(),
            z3_apply_result,
        }
    }

    pub fn list_subgoals(self) -> impl Iterator<Item = Goal> {
        let num_subgoals =
            unsafe { Z3_apply_result_get_num_subgoals(self.ctx.z3_ctx.0, self.z3_apply_result) };
        (0..num_subgoals).map(move |i| unsafe {
            Goal::wrap(
                &self.ctx,
                Z3_apply_result_get_subgoal(self.ctx.z3_ctx.0, self.z3_apply_result, i).unwrap(),
            )
        })
    }
}

impl Drop for ApplyResult {
    fn drop(&mut self) {
        unsafe {
            Z3_apply_result_dec_ref(self.ctx.z3_ctx.0, self.z3_apply_result);
        }
    }
}

impl Tactic {
    /// Iterate through the valid tactic names.
    ///
    /// # Example
    ///
    /// ```
    /// # use z3::Tactic;
    /// let tactics: Vec<_> = Tactic::list_all().into_iter().filter_map(|r| r.ok()).collect();
    /// assert!(tactics.contains(&"ufbv".to_string()));
    /// ```
    pub fn list_all() -> Vec<Result<String, Utf8Error>> {
        let ctx = &Context::thread_local();
        let p = unsafe { Z3_get_num_tactics(ctx.z3_ctx.0) };
        (0..p)
            .map(move |n| {
                let t = unsafe { Z3_get_tactic_name(ctx.z3_ctx.0, n) };
                unsafe { CStr::from_ptr(t) }.to_str().map(String::from)
            })
            .collect()
    }

    unsafe fn wrap(ctx: &Context, z3_tactic: Z3_tactic) -> Tactic {
        unsafe {
            Z3_tactic_inc_ref(ctx.z3_ctx.0, z3_tactic);
        }
        Tactic {
            ctx: ctx.clone(),
            z3_tactic,
        }
    }

    /// Create a tactic by name.
    ///
    /// # Example
    ///
    /// ```
    /// # use z3::Tactic;
    /// let tactic = Tactic::new("nlsat");
    /// ```
    ///
    /// # See also
    ///
    /// - [`Tactic::list_all()`]
    pub fn new(name: &str) -> Tactic {
        let ctx = &Context::thread_local();
        let tactic_name = CString::new(name).unwrap();

        unsafe {
            let tactic = Z3_mk_tactic(ctx.z3_ctx.0, tactic_name.as_ptr())
                .unwrap_or_else(|| panic!("{name} is an invalid tactic"));
            Self::wrap(ctx, tactic)
        }
    }

    /// Return a tactic that just return the given goal.
    pub fn create_skip() -> Tactic {
        let ctx = &Context::thread_local();
        unsafe { Self::wrap(ctx, Z3_tactic_skip(ctx.z3_ctx.0).unwrap()) }
    }

    /// Return a tactic that always fails.
    pub fn create_fail() -> Tactic {
        let ctx = &Context::thread_local();
        unsafe { Self::wrap(ctx, Z3_tactic_fail(ctx.z3_ctx.0).unwrap()) }
    }

    /// Return a tactic that keeps applying `t` until the goal is not modified anymore or the maximum
    /// number of iterations `max` is reached.
    pub fn repeat(t: &Tactic, max: u32) -> Tactic {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(
                ctx,
                Z3_tactic_repeat(ctx.z3_ctx.0, t.z3_tactic, max).unwrap(),
            )
        }
    }

    /// Return a tactic that applies the current tactic to a given goal, failing
    /// if it doesn't terminate within the period specified by `timeout`.
    pub fn try_for(&self, timeout: Duration) -> Tactic {
        let timeout_ms = c_uint::try_from(timeout.as_millis()).unwrap_or(c_uint::MAX);
        unsafe {
            Self::wrap(
                &self.ctx,
                Z3_tactic_try_for(self.ctx.z3_ctx.0, self.z3_tactic, timeout_ms).unwrap(),
            )
        }
    }

    /// Return a tactic that applies the current tactic to a given goal and
    /// the `then_tactic` to every subgoal produced by the original tactic.
    pub fn and_then(&self, then_tactic: &Tactic) -> Tactic {
        unsafe {
            Self::wrap(
                &self.ctx,
                Z3_tactic_and_then(self.ctx.z3_ctx.0, self.z3_tactic, then_tactic.z3_tactic)
                    .unwrap(),
            )
        }
    }

    /// Return a tactic that current tactic to a given goal,
    /// if it fails then returns the result of `else_tactic` applied to the given goal.
    pub fn or_else(&self, else_tactic: &Tactic) -> Tactic {
        unsafe {
            Self::wrap(
                &self.ctx,
                Z3_tactic_or_else(self.ctx.z3_ctx.0, self.z3_tactic, else_tactic.z3_tactic)
                    .unwrap(),
            )
        }
    }

    /// Return a tactic that applies self to a given goal if the probe `p` evaluates to true,
    /// and `t` if `p` evaluates to false.
    pub fn probe_or_else(&self, p: &Probe, t: &Tactic) -> Tactic {
        unsafe {
            Self::wrap(
                &self.ctx,
                Z3_tactic_cond(self.ctx.z3_ctx.0, p.z3_probe, self.z3_tactic, t.z3_tactic).unwrap(),
            )
        }
    }

    /// Return a tactic that applies itself to a given goal if the probe `p` evaluates to true.
    /// If `p` evaluates to false, then the new tactic behaves like the skip tactic.
    pub fn when(&self, p: &Probe) -> Tactic {
        unsafe {
            Self::wrap(
                &self.ctx,
                Z3_tactic_when(self.ctx.z3_ctx.0, p.z3_probe, self.z3_tactic).unwrap(),
            )
        }
    }

    /// Return a tactic that applies `t1` to a given goal if the probe `p` evaluates to true,
    /// and `t2` if `p` evaluates to false.
    pub fn cond(p: &Probe, t1: &Tactic, t2: &Tactic) -> Tactic {
        assert_eq!(p.ctx, t1.ctx);
        assert_eq!(t1.ctx, t2.ctx);
        unsafe {
            Self::wrap(
                &p.ctx,
                Z3_tactic_cond(p.ctx.z3_ctx.0, p.z3_probe, t1.z3_tactic, t2.z3_tactic).unwrap(),
            )
        }
    }

    /// Return a tactic that fails if the probe `p` evaluates to false.
    pub fn fail_if(p: &Probe) -> Tactic {
        unsafe {
            Self::wrap(
                &p.ctx,
                Z3_tactic_fail_if(p.ctx.z3_ctx.0, p.z3_probe).unwrap(),
            )
        }
    }

    /// Return a tactic that applies the current tactic using the given set of parameters.
    pub fn with(&self, params: &Params) -> Tactic {
        unsafe {
            Self::wrap(
                &self.ctx,
                Z3_tactic_using_params(self.ctx.z3_ctx.0, self.z3_tactic, params.z3_params)
                    .unwrap(),
            )
        }
    }

    /// Attempts to apply the tactic to `goal`. If the tactic succeeds, returns
    /// `Ok(_)` with a `ApplyResult`. If the tactic fails, returns `Err(_)` with
    /// an error message describing why.
    pub fn apply(&self, goal: &Goal, params: Option<&Params>) -> Result<ApplyResult, String> {
        unsafe {
            let z3_apply_result = match params {
                None => Z3_tactic_apply(self.ctx.z3_ctx.0, self.z3_tactic, goal.z3_goal),
                Some(params) => Z3_tactic_apply_ex(
                    self.ctx.z3_ctx.0,
                    self.z3_tactic,
                    goal.z3_goal,
                    params.z3_params,
                ),
            };
            if let Some(z3_apply_result) = z3_apply_result {
                Ok(ApplyResult::wrap(&self.ctx, z3_apply_result))
            } else {
                let code = Z3_get_error_code(self.ctx.z3_ctx.0);
                let msg = Z3_get_error_msg(self.ctx.z3_ctx.0, code);
                Err(String::from(CStr::from_ptr(msg).to_str().unwrap_or(
                    "Couldn't retrieve error message from z3: got invalid UTF-8",
                )))
            }
        }
    }

    /// Create a new solver that is implemented using the given tactic.
    ///
    /// # Example
    ///
    /// ```
    /// # use z3::{ast, SatResult, Tactic};
    ///
    /// let tactic = Tactic::new("qfnra");
    /// let solver = tactic.solver();
    ///
    /// let x = ast::Int::new_const("x");
    /// let y = ast::Int::new_const("y");
    ///
    /// solver.assert(&x.gt(&y));
    /// assert_eq!(solver.check(), SatResult::Sat);
    /// ```
    ///
    pub fn solver(&self) -> Solver {
        unsafe {
            Solver::wrap(
                &self.ctx,
                Z3_mk_solver_from_tactic(self.ctx.z3_ctx.0, self.z3_tactic).unwrap(),
            )
        }
    }
}

impl fmt::Display for Tactic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let p = unsafe { Z3_tactic_get_help(self.ctx.z3_ctx.0, self.z3_tactic) };
        if p.is_null() {
            return Result::Err(fmt::Error);
        }
        match unsafe { CStr::from_ptr(p) }.to_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Result::Err(fmt::Error),
        }
    }
}

impl fmt::Debug for Tactic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl Drop for Tactic {
    fn drop(&mut self) {
        unsafe {
            Z3_tactic_dec_ref(self.ctx.z3_ctx.0, self.z3_tactic);
        }
    }
}
