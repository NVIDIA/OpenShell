use crate::ast::IntoAst;
use crate::ast::{Ast, Bool, Int, binop, unop};
use crate::{Context, Sort, Symbol};
use std::ffi::CString;
use z3_sys::*;

/// [`Ast`] node representing a bitvector value.
pub struct BV {
    pub(crate) ctx: Context,
    pub(crate) z3_ast: Z3_ast,
}

macro_rules! bv_overflow_check_signed {
    (
        $(
            $( #[ $attr:meta ] )* $f:ident ( $z3fn:ident ) ;
        )*
    ) => {
        $(
            $( #[ $attr ] )*
            pub fn $f(&self, other: &BV, b: bool) -> Bool {
                unsafe {
                    Ast::wrap(&self.ctx, {
                        $z3fn(self.ctx.z3_ctx.0, self.z3_ast, other.z3_ast, b).unwrap()
                    })
                }
            }
        )*
    };
}

impl BV {
    pub fn from_str(sz: u32, value: &str) -> Option<BV> {
        let ctx = &Context::thread_local();
        let sort = Sort::bitvector(sz);
        let ast = unsafe {
            let bv_cstring = CString::new(value).unwrap();
            Z3_mk_numeral(ctx.z3_ctx.0, bv_cstring.as_ptr(), sort.z3_sort)?
        };
        Some(unsafe { Self::wrap(ctx, ast) })
    }

    /// Create a BV from an array of bits.
    ///
    /// # Examples
    /// ```
    /// # use z3::{ast::{Ast, BV}, Config, Context, Solver};
    /// // 0b00000010
    /// let bv = BV::from_bits(&[false, true, false, false, false, false, false, false]).unwrap();
    /// let bv_none = BV::from_bits(&[]);
    /// assert_eq!(bv, 2);
    /// assert_eq!(bv_none, None);
    /// ```
    pub fn from_bits(bits: &[bool]) -> Option<BV> {
        let ctx = &Context::thread_local();
        let ast = unsafe { Z3_mk_bv_numeral(ctx.z3_ctx.0, bits.len() as u32, bits.as_ptr())? };
        Some(unsafe { Self::wrap(ctx, ast) })
    }

    pub fn new_const<S: Into<Symbol>>(name: S, sz: u32) -> BV {
        let ctx = &Context::thread_local();
        let sort = Sort::bitvector(sz);
        unsafe {
            Self::wrap(ctx, {
                Z3_mk_const(ctx.z3_ctx.0, name.into().as_z3_symbol(), sort.z3_sort).unwrap()
            })
        }
    }

    pub fn fresh_const(prefix: &str, sz: u32) -> BV {
        let ctx = &Context::thread_local();
        let sort = Sort::bitvector(sz);
        unsafe {
            Self::wrap(ctx, {
                let pp = CString::new(prefix).unwrap();
                let p = pp.as_ptr();
                Z3_mk_fresh_const(ctx.z3_ctx.0, p, sort.z3_sort).unwrap()
            })
        }
    }

    pub fn from_i64(i: i64, sz: u32) -> BV {
        let ctx = &Context::thread_local();
        let sort = Sort::bitvector(sz);
        unsafe { Self::wrap(ctx, Z3_mk_int64(ctx.z3_ctx.0, i, sort.z3_sort).unwrap()) }
    }

    pub fn from_u64(u: u64, sz: u32) -> BV {
        let ctx = &Context::thread_local();
        let sort = Sort::bitvector(sz);
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

    /// Create a bit vector from an integer.
    ///
    /// The bit vector will have width `sz`.
    ///
    /// # Examples
    /// ```
    /// # use z3::{ast, Config, Context, SatResult, Solver};
    /// # use z3::ast::Ast;
    /// # let solver = Solver::new();
    /// let i = ast::Int::new_const("x");
    /// solver.assert(&i.eq(&ast::Int::from_i64(-3)));
    ///
    /// let x = ast::BV::from_int(&i, 64);
    /// assert_eq!(64, x.get_size());
    ///
    /// assert_eq!(solver.check(), SatResult::Sat);
    /// let model = solver.get_model().unwrap();
    ///
    /// assert_eq!(-3, model.eval(&x.to_int(true), true).unwrap().as_i64().expect("as_i64() shouldn't fail"));
    /// ```
    pub fn from_int(ast: &Int, sz: u32) -> BV {
        unsafe {
            Self::wrap(
                &ast.ctx,
                Z3_mk_int2bv(ast.ctx.z3_ctx.0, sz, ast.z3_ast).unwrap(),
            )
        }
    }

    /// Create an integer from a bitvector.
    /// This is just a convenience wrapper around
    /// [`Int::from_bv()`]; see notes there.
    pub fn to_int(&self, signed: bool) -> Int {
        Int::from_bv(self, signed)
    }

    /// Get the size of the bitvector (in bits)
    pub fn get_size(&self) -> u32 {
        let sort = self.get_sort();
        unsafe { Z3_get_bv_sort_size(self.ctx.z3_ctx.0, sort.z3_sort) }
    }

    // Bitwise ops
    unop! {
        /// Bitwise negation
        bvnot(Z3_mk_bvnot, Self);
        /// Two's complement negation
        bvneg(Z3_mk_bvneg, Self);
        /// Conjunction of all the bits in the vector. Returns a BV with size (bitwidth) 1.
        bvredand(Z3_mk_bvredand, Self);
        /// Disjunction of all the bits in the vector. Returns a BV with size (bitwidth) 1.
        bvredor(Z3_mk_bvredor, Self);
    }
    binop! {
        /// Bitwise and
        bvand(Z3_mk_bvand, Self);
        /// Bitwise or
        bvor(Z3_mk_bvor, Self);
        /// Bitwise exclusive-or
        bvxor(Z3_mk_bvxor, Self);
        /// Bitwise nand
        bvnand(Z3_mk_bvnand, Self);
        /// Bitwise nor
        bvnor(Z3_mk_bvnor, Self);
        /// Bitwise xnor
        bvxnor(Z3_mk_bvxnor, Self);
    }

    // Arithmetic ops
    binop! {
        /// Addition
        bvadd(Z3_mk_bvadd, Self);
        /// Subtraction
        bvsub(Z3_mk_bvsub, Self);
        /// Multiplication
        bvmul(Z3_mk_bvmul, Self);
        /// Unsigned division
        bvudiv(Z3_mk_bvudiv, Self);
        /// Signed division
        bvsdiv(Z3_mk_bvsdiv, Self);
        /// Unsigned remainder
        bvurem(Z3_mk_bvurem, Self);
        /// Signed remainder (sign follows dividend)
        bvsrem(Z3_mk_bvsrem, Self);
        /// Signed remainder (sign follows divisor)
        bvsmod(Z3_mk_bvsmod, Self);
    }

    // Comparison ops
    binop! {
        /// Unsigned less than
        bvult(Z3_mk_bvult, Bool);
        /// Signed less than
        bvslt(Z3_mk_bvslt, Bool);
        /// Unsigned less than or equal
        bvule(Z3_mk_bvule, Bool);
        /// Signed less than or equal
        bvsle(Z3_mk_bvsle, Bool);
        /// Unsigned greater or equal
        bvuge(Z3_mk_bvuge, Bool);
        /// Signed greater or equal
        bvsge(Z3_mk_bvsge, Bool);
        /// Unsigned greater than
        bvugt(Z3_mk_bvugt, Bool);
        /// Signed greater than
        bvsgt(Z3_mk_bvsgt, Bool);
    }

    // Shift ops
    binop! {
        /// Shift left
        bvshl(Z3_mk_bvshl, Self);
        /// Logical shift right (add zeroes in the high bits)
        bvlshr(Z3_mk_bvlshr, Self);
        /// Arithmetic shift right (sign-extend in the high bits)
        bvashr(Z3_mk_bvashr, Self);
        /// Rotate left
        bvrotl(Z3_mk_ext_rotate_left, Self);
        /// Rotate right
        bvrotr(Z3_mk_ext_rotate_right, Self);
    }

    binop! {
        /// Concatenate two bitvectors
        concat(Z3_mk_concat, Self);
    }

    // overflow checks
    unop! {
        /// Check if negation overflows
        bvneg_no_overflow(Z3_mk_bvneg_no_overflow, Bool);
    }
    bv_overflow_check_signed! {
        /// Check if addition overflows
        bvadd_no_overflow(Z3_mk_bvadd_no_overflow);
        /// Check if subtraction underflows
        bvsub_no_underflow(Z3_mk_bvsub_no_underflow);
        /// Check if multiplication overflows
        bvmul_no_overflow(Z3_mk_bvmul_no_overflow);
    }
    binop! {
        /// Check if addition underflows
        bvadd_no_underflow(Z3_mk_bvadd_no_underflow, Bool);
        /// Check if subtraction overflows
        bvsub_no_overflow(Z3_mk_bvsub_no_overflow, Bool);
        /// Check if signed division overflows
        bvsdiv_no_overflow(Z3_mk_bvsdiv_no_overflow, Bool);
        /// Check if multiplication underflows
        bvmul_no_underflow(Z3_mk_bvmul_no_underflow, Bool);
    }

    /// Extract the bits `high` down to `low` from the bitvector.
    /// Returns a bitvector of size `n`, where `n = high - low + 1`.
    pub fn extract(&self, high: u32, low: u32) -> Self {
        unsafe {
            Self::wrap(&self.ctx, {
                Z3_mk_extract(self.ctx.z3_ctx.0, high, low, self.z3_ast).unwrap()
            })
        }
    }

    /// Sign-extend the bitvector to size `m+i`, where `m` is the original size of the bitvector.
    /// That is, `i` bits will be added.
    pub fn sign_ext(&self, i: u32) -> Self {
        unsafe {
            Self::wrap(&self.ctx, {
                Z3_mk_sign_ext(self.ctx.z3_ctx.0, i, self.z3_ast).unwrap()
            })
        }
    }

    /// Zero-extend the bitvector to size `m+i`, where `m` is the original size of the bitvector.
    /// That is, `i` bits will be added.
    pub fn zero_ext(&self, i: u32) -> Self {
        unsafe {
            Self::wrap(&self.ctx, {
                Z3_mk_zero_ext(self.ctx.z3_ctx.0, i, self.z3_ast).unwrap()
            })
        }
    }
}

macro_rules! into_bv {
    ($t:ty) => {
        impl IntoAst<BV> for $t {
            fn into_ast(self, a: &BV) -> BV {
                BV::from_u64(self as u64, a.get_size())
            }
        }
    };
}

macro_rules! into_bv_signed {
    ($t:ty) => {
        impl IntoAst<BV> for $t {
            fn into_ast(self, a: &BV) -> BV {
                BV::from_i64(self as i64, a.get_size())
            }
        }
    };
}

into_bv!(u8);
into_bv!(u16);
into_bv!(u32);
into_bv!(u64);

into_bv_signed!(i8);
into_bv_signed!(i16);
into_bv_signed!(i32);
into_bv_signed!(i64);
