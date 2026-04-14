use crate::ast::Ast;
use crate::ast::{Bool, Int, binop, unop, varop};
use crate::{Context, Sort, Symbol};
use num::BigRational;
use std::ffi::{CStr, CString};
use z3_sys::*;

/// [`Ast`] node representing a real value.
pub struct Real {
    pub(crate) ctx: Context,
    pub(crate) z3_ast: Z3_ast,
}
impl Real {
    pub fn from_big_rational(value: &BigRational) -> Real {
        let num = value.numer();
        let den = value.denom();
        Real::from_rational_str(&num.to_str_radix(10), &den.to_str_radix(10)).unwrap()
    }

    #[deprecated = "Please use from_rational_str instead"]
    pub fn from_real_str(num: &str, den: &str) -> Option<Real> {
        Self::from_rational_str(num, den)
    }

    pub fn from_rational_str(num: &str, den: &str) -> Option<Real> {
        let ctx = &Context::thread_local();
        let sort = Sort::real();
        let ast = unsafe {
            let fraction_cstring = CString::new(format!("{num:} / {den:}")).unwrap();
            Z3_mk_numeral(ctx.z3_ctx.0, fraction_cstring.as_ptr(), sort.z3_sort)?
        };
        Some(unsafe { Real::wrap(ctx, ast) })
    }
}
impl Real {
    pub fn new_const<S: Into<Symbol>>(name: S) -> Real {
        let ctx = &Context::thread_local();
        let sort = Sort::real();
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_const(ctx.z3_ctx.0, name.into().as_z3_symbol(), sort.z3_sort).unwrap()
            })
        }
    }

    pub fn fresh_const(prefix: &str) -> Real {
        let ctx = &Context::thread_local();
        let sort = Sort::real();
        unsafe {
            Self::wrap(ctx, {
                let pp = CString::new(prefix).unwrap();
                let p = pp.as_ptr();
                Z3_mk_fresh_const(ctx.z3_ctx.0, p, sort.z3_sort).unwrap()
            })
        }
    }

    #[deprecated = "Please use from_rational instead"]
    pub fn from_real(num: i32, den: i32) -> Real {
        Self::from_rational(num as i64, den as i64)
    }

    pub fn from_rational(num: i64, den: i64) -> Real {
        let ctx = &Context::thread_local();
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_real(
                    ctx.z3_ctx.0,
                    num as ::std::os::raw::c_int,
                    den as ::std::os::raw::c_int,
                )
                .unwrap()
            })
        }
    }

    #[deprecated = "Please use as_rational instead"]
    pub fn as_real(&self) -> Option<(i64, i64)> {
        self.as_rational()
    }

    pub fn as_rational(&self) -> Option<(i64, i64)> {
        unsafe {
            let mut num: i64 = 0;
            let mut den: i64 = 0;
            if Z3_get_numeral_small(self.ctx.z3_ctx.0, self.z3_ast, &mut num, &mut den) {
                Some((num, den))
            } else {
                None
            }
        }
    }

    pub fn approx(&self, precision: usize) -> ::std::string::String {
        let s = unsafe {
            CStr::from_ptr(Z3_get_numeral_decimal_string(
                self.ctx.z3_ctx.0,
                self.z3_ast,
                precision as _,
            ))
        }
        .to_str()
        .unwrap();
        s.strip_suffix('?').unwrap_or(s).to_owned()
    }
    pub fn approx_f64(&self) -> f64 {
        self.approx(17).parse().unwrap() // 17 decimal digits needed to get full f64 precision
    }

    pub fn from_int(ast: &Int) -> Real {
        unsafe {
            Self::wrap(
                &ast.ctx,
                Z3_mk_int2real(ast.ctx.z3_ctx.0, ast.z3_ast).unwrap(),
            )
        }
    }

    /// Create an integer from a real.
    /// This is just a convenience wrapper around
    /// [`Int::from_real()`]; see notes there.
    pub fn to_int(&self) -> Int {
        Int::from_real(self)
    }

    unop! {
        is_int(Z3_mk_is_int, Bool);
    }

    varop! {
        add(Z3_mk_add, Self);
        sub(Z3_mk_sub, Self);
        mul(Z3_mk_mul, Self);
    }
    unop! {
        unary_minus(Z3_mk_unary_minus, Self);
    }
    binop! {
        div(Z3_mk_div, Self);
        power(Z3_mk_power, Self);
        lt(Z3_mk_lt, Bool);
        le(Z3_mk_le, Bool);
        gt(Z3_mk_gt, Bool);
        ge(Z3_mk_ge, Bool);
    }
}

impl From<BigRational> for Real {
    fn from(v: BigRational) -> Real {
        Real::from_big_rational(&v)
    }
}
