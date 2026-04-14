use crate::ast::{Ast, Bool};
use crate::{Context, Fixedpoint, FuncDecl, Params, SatResult, Statistics};
use std::ffi::CString;
use std::fmt;
use z3_sys::*;

impl Drop for Fixedpoint {
    fn drop(&mut self) {
        unsafe {
            Z3_fixedpoint_dec_ref(self.ctx.z3_ctx.0, self.z3_fp);
        }
    }
}

impl Fixedpoint {
    /// Create a new fixedpoint context.
    pub fn new() -> Fixedpoint {
        let ctx = Context::thread_local();
        unsafe {
            let fp = Z3_mk_fixedpoint(ctx.z3_ctx.0).unwrap();
            Z3_fixedpoint_inc_ref(ctx.z3_ctx.0, fp);
            Fixedpoint {
                ctx: ctx.clone(),
                z3_fp: fp,
            }
        }
    }

    /// Add a Horn clause rule to the fixedpoint context.
    ///
    /// # Example
    /// ```
    /// # use z3::ast::*;
    /// # use z3::Fixedpoint;
    /// let fp = Fixedpoint::new();
    /// let p = Bool::new_const("p");
    /// let q = Bool::new_const("q");
    ///
    /// // Add rule: p => q
    /// fp.add_rule(&p.implies(&q), None);
    /// ```
    pub fn add_rule(&self, rule: &impl Ast, name: Option<&str>) {
        let name_sym = name.map(|name| {
            let cname = CString::new(name).unwrap();
            unsafe { Z3_mk_string_symbol(self.ctx.z3_ctx.0, cname.as_ptr()).unwrap() }
        });
        unsafe {
            Z3_fixedpoint_add_rule(self.ctx.z3_ctx.0, self.z3_fp, rule.get_z3_ast(), name_sym);
        }
    }

    /// Add a fact (ground assertion) to the fixedpoint context.
    pub fn add_fact(&self, pred: &FuncDecl, args: &[u32]) {
        let mut args: Vec<u32> = args.to_vec();
        unsafe {
            Z3_fixedpoint_add_fact(
                self.ctx.z3_ctx.0,
                self.z3_fp,
                pred.z3_func_decl,
                args.len() as u32,
                args.as_mut_ptr(),
            );
        }
    }

    /// Assert a formula in the fixedpoint context.
    pub fn assert(&self, axiom: &impl Ast) {
        unsafe {
            Z3_fixedpoint_assert(self.ctx.z3_ctx.0, self.z3_fp, axiom.get_z3_ast());
        }
    }

    /// Query the fixedpoint context for satisfiability.
    ///
    /// Returns the result of the query (satisfiable, unsatisfiable, or unknown).
    pub fn query(&self, query: &impl Ast) -> SatResult {
        unsafe {
            match Z3_fixedpoint_query(self.ctx.z3_ctx.0, self.z3_fp, query.get_z3_ast()) {
                Z3_L_TRUE => SatResult::Sat,
                Z3_L_FALSE => SatResult::Unsat,
                _ => SatResult::Unknown,
            }
        }
    }

    /// Query the fixedpoint context with multiple relations.
    pub fn query_relations(&self, relations: &[&FuncDecl]) -> SatResult {
        let decls: Vec<Z3_func_decl> = relations.iter().map(|r| r.z3_func_decl).collect();
        unsafe {
            match Z3_fixedpoint_query_relations(
                self.ctx.z3_ctx.0,
                self.z3_fp,
                decls.len() as u32,
                decls.as_ptr(),
            ) {
                Z3_L_TRUE => SatResult::Sat,
                Z3_L_FALSE => SatResult::Unsat,
                _ => SatResult::Unknown,
            }
        }
    }

    /// Get the answer substitution after a successful query.
    /// This provides the concrete values that make the query satisfiable.
    pub fn get_answer(&self) -> Option<Bool> {
        unsafe {
            let answer = Z3_fixedpoint_get_answer(self.ctx.z3_ctx.0, self.z3_fp);
            answer.map(|answer| Bool::wrap(&self.ctx, answer))
        }
    }

    /// Get the reason (core) for unsatisfiability after an unsuccessful query.
    pub fn get_reason_unknown(&self) -> String {
        unsafe {
            let reason = Z3_fixedpoint_get_reason_unknown(self.ctx.z3_ctx.0, self.z3_fp);
            std::ffi::CStr::from_ptr(reason)
                .to_string_lossy()
                .into_owned()
        }
    }

    /// Update a named rule.
    pub fn update_rule(&self, rule: &impl Ast, name: &str) {
        unsafe {
            let cname = CString::new(name).unwrap();
            let name_sym = Z3_mk_string_symbol(self.ctx.z3_ctx.0, cname.as_ptr()).unwrap();
            Z3_fixedpoint_update_rule(self.ctx.z3_ctx.0, self.z3_fp, rule.get_z3_ast(), name_sym);
        }
    }

    /// Get the number of levels explored during the last query.
    pub fn get_num_levels(&self, pred: &FuncDecl) -> u32 {
        unsafe { Z3_fixedpoint_get_num_levels(self.ctx.z3_ctx.0, self.z3_fp, pred.z3_func_decl) }
    }

    /// Get the cover (approximation) at a given level.
    pub fn get_cover_delta(&self, level: i32, predicate: &FuncDecl) -> Option<Bool> {
        unsafe {
            Z3_fixedpoint_get_cover_delta(
                self.ctx.z3_ctx.0,
                self.z3_fp,
                level,
                predicate.z3_func_decl,
            )
            .map(|d| Bool::wrap(&self.ctx, d))
        }
    }

    /// Add a cover for a predicate at a given level.
    pub fn add_cover(&self, level: i32, predicate: &FuncDecl, property: &impl Ast) {
        unsafe {
            Z3_fixedpoint_add_cover(
                self.ctx.z3_ctx.0,
                self.z3_fp,
                level,
                predicate.z3_func_decl,
                property.get_z3_ast(),
            );
        }
    }

    /// Get statistics about the last query.
    pub fn get_statistics(&self) -> Statistics {
        unsafe {
            Statistics::wrap(
                &self.ctx,
                Z3_fixedpoint_get_statistics(self.ctx.z3_ctx.0, self.z3_fp).unwrap(),
            )
        }
    }

    /// Register a relation as fixedpoint-defined (least-fixedpoint semantics).
    pub fn register_relation(&self, pred: &FuncDecl) {
        unsafe {
            Z3_fixedpoint_register_relation(self.ctx.z3_ctx.0, self.z3_fp, pred.z3_func_decl);
        }
    }

    /// Set parameters for the fixedpoint context.
    pub fn set_params(&self, params: &Params) {
        unsafe {
            Z3_fixedpoint_set_params(self.ctx.z3_ctx.0, self.z3_fp, params.z3_params);
        }
    }

    /// Get the help string for fixedpoint parameters.
    pub fn get_help(&self) -> String {
        unsafe {
            let help = Z3_fixedpoint_get_help(self.ctx.z3_ctx.0, self.z3_fp);
            std::ffi::CStr::from_ptr(help)
                .to_string_lossy()
                .into_owned()
        }
    }

    /// Parse a fixedpoint problem from a string in SMT-LIB format.
    pub fn from_string(&self, s: &str) -> Result<(), String> {
        let cs = CString::new(s).map_err(|_| "String contains null byte")?;
        unsafe {
            let result = Z3_fixedpoint_from_string(self.ctx.z3_ctx.0, self.z3_fp, cs.as_ptr());
            match result {
                Some(_) => Ok(()),
                None => Err("Failed to parse fixedpoint from string".to_string()),
            }
        }
    }

    /// Parse a file containing a fixedpoint problem.
    pub fn from_file(&self, filename: &str) -> Result<(), String> {
        let cs = CString::new(filename).map_err(|_| "Filename contains null byte")?;
        unsafe {
            let result = Z3_fixedpoint_from_file(self.ctx.z3_ctx.0, self.z3_fp, cs.as_ptr());
            match result {
                Some(_) => Ok(()),
                None => Err("Failed to parse fixedpoint from file".to_string()),
            }
        }
    }
}

impl Default for Fixedpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Fixedpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let s = unsafe {
            let s = Z3_fixedpoint_to_string(self.ctx.z3_ctx.0, self.z3_fp, 0, std::ptr::null_mut());
            std::ffi::CStr::from_ptr(s).to_string_lossy().into_owned()
        };
        write!(f, "{s}")
    }
}

impl fmt::Debug for Fixedpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}
