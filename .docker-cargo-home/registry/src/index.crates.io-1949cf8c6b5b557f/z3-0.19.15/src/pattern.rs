use std::convert::TryInto;
use std::ffi::CStr;
use std::fmt;
use z3_sys::*;

use crate::{Context, Pattern, ast::Ast};

impl Pattern {
    /// Create a pattern for quantifier instantiation.
    ///
    /// Z3 uses pattern matching to instantiate quantifiers. If a
    /// pattern is not provided for a quantifier, then Z3 will
    /// automatically compute a set of patterns for it. However, for
    /// optimal performance, the user should provide the patterns.
    ///
    /// Patterns comprise a list of terms. The list should be
    /// non-empty.  If the list comprises of more than one term, it is
    /// a called a multi-pattern.
    ///
    /// In general, one can pass in a list of (multi-)patterns in the
    /// quantifier constructor.
    ///
    /// # See also:
    ///
    /// - `ast::forall_const()`
    /// - `ast::exists_const()`
    pub fn new(terms: &[&dyn Ast]) -> Pattern {
        let ctx = &Context::thread_local();
        assert!(!terms.is_empty());
        assert!(terms.iter().all(|t| t.get_ctx().z3_ctx == ctx.z3_ctx));

        let terms: Vec<_> = terms.iter().map(|t| t.get_z3_ast()).collect();

        Pattern {
            ctx: ctx.clone(),
            z3_pattern: unsafe {
                let p = Z3_mk_pattern(
                    ctx.z3_ctx.0,
                    terms.len().try_into().unwrap(),
                    terms.as_ptr() as *const Z3_ast,
                )
                .unwrap();
                Z3_inc_ref(ctx.z3_ctx.0, Z3_pattern_to_ast(ctx.z3_ctx.0, p).unwrap());
                p
            },
        }
    }
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let p = unsafe { Z3_pattern_to_string(self.ctx.z3_ctx.0, self.z3_pattern) };
        if p.is_null() {
            return Result::Err(fmt::Error);
        }
        match unsafe { CStr::from_ptr(p) }.to_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Result::Err(fmt::Error),
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl Drop for Pattern {
    fn drop(&mut self) {
        let ast = unsafe { Z3_pattern_to_ast(self.ctx.z3_ctx.0, self.z3_pattern) }.unwrap();
        unsafe {
            Z3_dec_ref(self.ctx.z3_ctx.0, ast);
        }
    }
}
