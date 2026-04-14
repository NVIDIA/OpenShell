use crate::Context;
use crate::ast::Ast;
use std::ffi::CString;
use z3_sys::*;

/// [`Ast`] node representing a regular expression.
/// ```
/// use z3::ast;
/// use z3::{Config, Context, Solver, SatResult};
///
/// let solver = Solver::new();
/// let s = ast::String::new_const("s");
///
/// // the regexp representing foo[a-c]*
/// let a = ast::Regexp::concat(&[
///     &ast::Regexp::literal("foo"),
///     &ast::Regexp::range(&'a', &'c').star()
/// ]);
/// // the regexp representing [a-z]+
/// let b = ast::Regexp::range(&'a', &'z').plus();
/// // intersection of a and b is non-empty
/// let intersect = ast::Regexp::intersect(&[&a, &b]);
/// solver.assert(&s.regex_matches(&intersect));
/// assert_eq!(solver.check(), SatResult::Sat);
/// ```
pub struct Regexp {
    pub(crate) ctx: Context,
    pub(crate) z3_ast: Z3_ast,
}

impl Regexp {
    /// Creates a regular expression that recognizes the string given as parameter
    pub fn literal(s: &str) -> Self {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(ctx, {
                let c_str = CString::new(s).unwrap();
                Z3_mk_seq_to_re(
                    ctx.z3_ctx.0,
                    Z3_mk_string(ctx.z3_ctx.0, c_str.as_ptr()).unwrap(),
                )
                .unwrap()
            })
        }
    }

    /// Creates a regular expression that recognizes a character in the specified range (e.g.
    /// `[a-z]`)
    pub fn range(lo: &char, hi: &char) -> Self {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(ctx, {
                let lo_cs = CString::new(lo.to_string()).unwrap();
                let hi_cs = CString::new(hi.to_string()).unwrap();
                let lo_z3s = Z3_mk_string(ctx.z3_ctx.0, lo_cs.as_ptr()).unwrap();
                Z3_inc_ref(ctx.z3_ctx.0, lo_z3s);
                let hi_z3s = Z3_mk_string(ctx.z3_ctx.0, hi_cs.as_ptr()).unwrap();
                Z3_inc_ref(ctx.z3_ctx.0, hi_z3s);

                let ret = Z3_mk_re_range(ctx.z3_ctx.0, lo_z3s, hi_z3s);
                Z3_dec_ref(ctx.z3_ctx.0, lo_z3s);
                Z3_dec_ref(ctx.z3_ctx.0, hi_z3s);
                ret.unwrap()
            })
        }
    }

    /// Creates a regular expression that recognizes this regular expression `lo` to `hi` times (e.g. `a{2,3}`)
    pub fn r#loop(&self, lo: u32, hi: u32) -> Self {
        unsafe {
            Self::wrap(&self.ctx, {
                Z3_mk_re_loop(self.ctx.z3_ctx.0, self.z3_ast, lo, hi).unwrap()
            })
        }
    }

    /// Creates a regular expression that recognizes this regular expression
    /// n number of times
    /// Requires Z3 4.8.15 or later.
    #[cfg(feature = "z3_4_8_15")]
    pub fn power(&self, n: u32) -> Self {
        unsafe {
            Self::wrap(&self.ctx, {
                Z3_mk_re_power(self.ctx.z3_ctx.0, self.z3_ast, n).unwrap()
            })
        }
    }

    /// Creates a regular expression that recognizes all sequences
    pub fn full() -> Self {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_re_full(
                    ctx.z3_ctx.0,
                    Z3_mk_re_sort(ctx.z3_ctx.0, Z3_mk_string_sort(ctx.z3_ctx.0).unwrap()).unwrap(),
                )
                .unwrap()
            })
        }
    }

    /// Creates a regular expression that accepts all singleton sequences of the characters
    /// Requires Z3 4.8.13 or later.
    #[cfg(feature = "z3_4_8_13")]
    pub fn allchar() -> Self {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_re_allchar(
                    ctx.z3_ctx.0,
                    Z3_mk_re_sort(ctx.z3_ctx.0, Z3_mk_string_sort(ctx.z3_ctx.0).unwrap()).unwrap(),
                )
                .unwrap()
            })
        }
    }

    /// Creates a regular expression that doesn't recognize any sequences
    pub fn empty() -> Self {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_re_empty(
                    ctx.z3_ctx.0,
                    Z3_mk_re_sort(ctx.z3_ctx.0, Z3_mk_string_sort(ctx.z3_ctx.0).unwrap()).unwrap(),
                )
                .unwrap()
            })
        }
    }

    crate::ast::unop! {
       /// Creates a regular expression that recognizes this regular expression one or more times (e.g. `a+`)
       plus(Z3_mk_re_plus, Self);
       /// Creates a regular expression that recognizes this regular expression any number of times
       /// (Kleene star, e.g. `a*`)
       star(Z3_mk_re_star, Self);
       /// Creates a regular expression that recognizes any sequence that this regular expression
       /// doesn't
       complement(Z3_mk_re_complement, Self);
       /// Creates a regular expression that optionally accepts this regular expression (e.g. `a?`)
       option(Z3_mk_re_option, Self);
    }
    #[cfg(feature = "z3_4_8_14")]
    crate::ast::binop! {
        /// Creates a difference regular expression
        /// Requires Z3 4.8.14 or later.
        diff(Z3_mk_re_diff, Self);
    }
    crate::ast::varop! {
       /// Concatenates regular expressions
        concat(Z3_mk_re_concat, Self);
       /// Creates a regular expression that recognizes sequences that any of the regular
       /// expressions given as parameters recognize
        union(Z3_mk_re_union, Self);
        /// Creates a regular expression that only recognizes sequences that all of the parameters
        /// recognize
        intersect(Z3_mk_re_intersect, Self);
    }
}
