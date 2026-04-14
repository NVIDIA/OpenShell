use crate::ast::{Ast, BV, Real, binop};
use crate::ast::{Bool, unop, varop};
use crate::{Context, Sort, Symbol};
use num::BigInt;
use std::ffi::CString;
use std::str::FromStr;
use z3_sys::*;

/// [`Ast`] node representing an integer value.
pub struct Int {
    pub(crate) ctx: Context,
    pub(crate) z3_ast: Z3_ast,
}
impl Int {
    pub fn from_big_int(value: &BigInt) -> Int {
        Int::from_str(&value.to_str_radix(10)).unwrap()
    }
}

impl Int {
    pub fn new_const<S: Into<Symbol>>(name: S) -> Int {
        let ctx = &Context::thread_local();
        let sort = Sort::int();
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_const(ctx.z3_ctx.0, name.into().as_z3_symbol(), sort.z3_sort).unwrap()
            })
        }
    }

    /// Declare and create a fresh Integer uninterpreted constant with name `prefix`.
    pub fn fresh_const(prefix: &str) -> Int {
        let ctx = &Context::thread_local();
        let sort = Sort::int();
        unsafe {
            Self::wrap(ctx, {
                let pp = CString::new(prefix).unwrap();
                let p = pp.as_ptr();
                Z3_mk_fresh_const(ctx.z3_ctx.0, p, sort.z3_sort).unwrap()
            })
        }
    }

    /// Create an AST node representing the integer value `i`.
    pub fn from_i64(i: i64) -> Int {
        let ctx = &Context::thread_local();
        let sort = Sort::int();
        unsafe { Self::wrap(ctx, Z3_mk_int64(ctx.z3_ctx.0, i, sort.z3_sort).unwrap()) }
    }

    /// Create an AST node representing the integer value `u`.
    pub fn from_u64(u: u64) -> Int {
        let ctx = &Context::thread_local();
        let sort = Sort::int();
        unsafe {
            Self::wrap(
                ctx,
                Z3_mk_unsigned_int64(ctx.z3_ctx.0, u, sort.z3_sort).unwrap(),
            )
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        unsafe {
            let mut tmp: ::std::os::raw::c_longlong = 0;
            if Z3_get_numeral_int64(self.ctx.z3_ctx.0, self.z3_ast, &mut tmp) {
                Some(tmp)
            } else {
                None
            }
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        unsafe {
            let mut tmp: ::std::os::raw::c_ulonglong = 0;
            if Z3_get_numeral_uint64(self.ctx.z3_ctx.0, self.z3_ast, &mut tmp) {
                Some(tmp)
            } else {
                None
            }
        }
    }

    pub fn from_real(ast: &Real) -> Int {
        unsafe {
            Self::wrap(
                &ast.ctx,
                Z3_mk_real2int(ast.ctx.z3_ctx.0, ast.z3_ast).unwrap(),
            )
        }
    }

    /// Create a real from an integer.
    /// This is just a convenience wrapper around
    /// [`Real::from_int()`]; see notes there.
    pub fn to_real(&self) -> Real {
        Real::from_int(self)
    }

    /// Create an integer from a bitvector.
    ///
    /// Signed and unsigned version.
    ///
    /// # Examples
    /// ```
    /// # use z3::{ast, Config, Context, SatResult, Solver};
    /// # use z3::ast::Ast;
    /// # let solver = Solver::new();
    /// let bv = ast::BV::new_const("x", 32);
    /// solver.assert(&bv._eq(&ast::BV::from_i64(-3, 32)));
    ///
    /// let x = ast::Int::from_bv(&bv, true);
    ///
    /// assert_eq!(solver.check(), SatResult::Sat);
    /// let model = solver.get_model().unwrap();
    ///
    /// assert_eq!(-3, model.eval(&x, true).unwrap().as_i64().unwrap());
    /// ```
    pub fn from_bv(ast: &BV, signed: bool) -> Int {
        unsafe {
            Self::wrap(&ast.ctx, {
                Z3_mk_bv2int(ast.ctx.z3_ctx.0, ast.z3_ast, signed).unwrap()
            })
        }
    }

    /// Create a bitvector from an integer.
    /// This is just a convenience wrapper around
    /// [`BV::from_int()`]; see notes there.
    pub fn to_ast(&self, sz: u32) -> BV {
        BV::from_int(self, sz)
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
        rem(Z3_mk_rem, Self);
        modulo(Z3_mk_mod, Self);
        power(Z3_mk_power, Real);
        lt(Z3_mk_lt, Bool);
        le(Z3_mk_le, Bool);
        gt(Z3_mk_gt, Bool);
        ge(Z3_mk_ge, Bool);
    }
    // Z3 does support mixing ints and reals in add(), sub(), mul(), div(), and power()
    //   (but not rem(), modulo(), lt(), le(), gt(), or ge()).
    // TODO: we could consider expressing this by having a Numeric trait with these methods.
    //    Int and Real would have the Numeric trait, but not the other Asts.
    // For example:
    //   fn add(&self, other: &impl Numeric) -> Dynamic { ... }
    // Note the return type would have to be Dynamic I think (?), as the exact result type
    //   depends on the particular types of the inputs.
    // Alternately, we could just have
    //   Int::add_real(&self, other: &Real) -> Real
    // and
    //   Real::add_int(&self, other: &Int) -> Real
    // This might be cleaner because we know exactly what the output type will be for these methods.
}

macro_rules! into_int {
    ($t:ty) => {
        impl From<$t> for Int {
            fn from(value: $t) -> Self {
                Int::from_u64(value as u64)
            }
        }
    };
}

macro_rules! into_int_signed {
    ($t:ty) => {
        impl From<$t> for Int {
            fn from(value: $t) -> Self {
                Int::from_i64(value as i64)
            }
        }
    };
}

into_int!(u8);
into_int!(u16);
into_int!(u32);
into_int!(u64);

into_int_signed!(i8);
into_int_signed!(i16);
into_int_signed!(i32);
into_int_signed!(i64);

impl From<BigInt> for Int {
    fn from(value: BigInt) -> Self {
        Int::from_big_int(&value)
    }
}

// todo: when we add a proper error type return that instead
impl FromStr for Int {
    type Err = ();
    fn from_str(value: &str) -> Result<Int, Self::Err> {
        let ctx = &Context::thread_local();
        let sort = Sort::int();
        let ast = unsafe {
            let int_cstring = CString::new(value).unwrap();
            Z3_mk_numeral(ctx.z3_ctx.0, int_cstring.as_ptr(), sort.z3_sort)
        }
        .ok_or(())?;
        Ok(unsafe { Int::wrap(ctx, ast) })
    }
}
