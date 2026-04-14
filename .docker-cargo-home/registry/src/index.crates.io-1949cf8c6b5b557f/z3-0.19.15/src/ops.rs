use crate::ast::{Bool, Float, IntoAst};
use std::iter::Product;
use std::iter::Sum;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Sub, SubAssign,
};

use crate::ast::{BV, Int, Real};

macro_rules! impl_unary_op_raw {
    ($ty:ty, $output:ty, $base_trait:ident, $base_fn:ident, $function:ident) => {
        impl $base_trait for $ty {
            type Output = $output;

            fn $base_fn(self) -> Self::Output {
                (&self as &$output).$function()
            }
        }
    };
}

macro_rules! impl_unary_op {
    ($ty:ident::$function:ident = $base_trait:ident::$base_fn:ident) => {
        impl_unary_op_raw!($ty, $ty, $base_trait, $base_fn, $function);
        impl_unary_op_raw!(&$ty, $ty, $base_trait, $base_fn, $function);
    };
}

impl_unary_op!(BV::bvnot = Not::not);
impl_unary_op!(BV::bvneg = Neg::neg);

macro_rules! impl_bin_trait {
    ($t:ident::$op:ident = $tr:ident::$trop:ident) => {
        impl<T: IntoAst<$t>> $tr<T> for $t {
            type Output = $t;
            fn $trop(self, rhs: T) -> Self::Output {
                let rhs = rhs.into_ast(&self);
                <$t>::$op(&self, rhs)
            }
        }

        impl<T: IntoAst<$t>> $tr<T> for &$t {
            type Output = $t;
            fn $trop(self, rhs: T) -> Self::Output {
                let rhs = rhs.into_ast(&self);
                <$t>::$op(&self, rhs)
            }
        }
    };
}

macro_rules! impl_bin_assign_trait {
    ($t:ident::$op:ident = $tr:ident::$trop:ident) => {
        impl<T: IntoAst<$t>> $tr<T> for $t {
            fn $trop(&mut self, rhs: T) {
                let res = (self as &mut $t).clone().$op(rhs);
                *self = res
            }
        }
    };
}

macro_rules! impl_var_trait {
    ($t:ident::$op:ident = $tr:ident::$trop:ident) => {
        impl<T: IntoAst<$t>> $tr<T> for $t {
            type Output = $t;
            fn $trop(self, rhs: T) -> Self::Output {
                let rhs = rhs.into_ast(&self);
                <$t>::$op(&[self.clone(), rhs])
            }
        }

        impl<T: IntoAst<$t>> $tr<T> for &$t {
            type Output = $t;
            fn $trop(self, rhs: T) -> Self::Output {
                let rhs = rhs.into_ast(&self);
                <$t>::$op(&[self.clone(), rhs])
            }
        }
    };
}

impl_var_trait!(Bool::and = BitAnd::bitand);
impl_var_trait!(Bool::or = BitOr::bitor);
impl_bin_trait!(Bool::xor = BitXor::bitxor);

impl_bin_assign_trait!(Bool::bitand = BitAndAssign::bitand_assign);
impl_bin_assign_trait!(Bool::bitor = BitOrAssign::bitor_assign);
impl_bin_assign_trait!(Bool::bitxor = BitXorAssign::bitxor_assign);

impl_bin_trait!(BV::bvadd = Add::add);
impl_bin_trait!(BV::bvsub = Sub::sub);
impl_bin_trait!(BV::bvmul = Mul::mul);
impl_bin_trait!(BV::bvand = BitAnd::bitand);
impl_bin_trait!(BV::bvor = BitOr::bitor);
impl_bin_trait!(BV::bvxor = BitXor::bitxor);
impl_bin_trait!(BV::bvshl = Shl::shl);

impl_bin_assign_trait!(BV::bvadd = AddAssign::add_assign);
impl_bin_assign_trait!(BV::bvsub = SubAssign::sub_assign);
impl_bin_assign_trait!(BV::bvmul = MulAssign::mul_assign);
impl_bin_assign_trait!(BV::bvand = BitAndAssign::bitand_assign);
impl_bin_assign_trait!(BV::bvor = BitOrAssign::bitor_assign);
impl_bin_assign_trait!(BV::bvxor = BitXorAssign::bitxor_assign);
impl_bin_assign_trait!(BV::bvshl = ShlAssign::shl_assign);

impl_unary_op!(Int::unary_minus = Neg::neg);

impl_var_trait!(Int::add = Add::add);
impl_var_trait!(Int::sub = Sub::sub);
impl_var_trait!(Int::mul = Mul::mul);
impl_bin_trait!(Int::div = Div::div);
impl_bin_trait!(Int::rem = Rem::rem);

impl_bin_assign_trait!(Int::add = AddAssign::add_assign);
impl_bin_assign_trait!(Int::sub = SubAssign::sub_assign);
impl_bin_assign_trait!(Int::mul = MulAssign::mul_assign);
impl_bin_assign_trait!(Int::div = DivAssign::div_assign);
impl_bin_assign_trait!(Int::rem = RemAssign::rem_assign);

impl_var_trait!(Real::add = Add::add);
impl_var_trait!(Real::sub = Sub::sub);
impl_var_trait!(Real::mul = Mul::mul);
impl_bin_trait!(Real::div = Div::div);
impl_unary_op!(Real::unary_minus = Neg::neg);

impl_bin_assign_trait!(Real::add = AddAssign::add_assign);
impl_bin_assign_trait!(Real::sub = SubAssign::sub_assign);
impl_bin_assign_trait!(Real::mul = MulAssign::mul_assign);
impl_bin_assign_trait!(Real::div = DivAssign::div_assign);

// implementations for Real
//
// // // implementations for Float
impl_unary_op!(Float::unary_neg = Neg::neg);
//
// // implementations for Bool
impl_unary_op!(Bool::not = Not::not);

// Impl bin ops for concrete types on the left-hand-side that people
// might want to use
// Note that this is not necessary when an Ast is on the left hand
// side because it is covered by a blanket impl of `IntoAst`. This
// does not work for the IntoAst being on the LHS because of the orphan
// rule
macro_rules! impl_trait_number_types {
    ($Z3ty:ty, $tr:ident::$op:ident, [$($num:ty),+]) => {
        $(
        impl_trait_number_types!($Z3ty, $tr::$op, $num);
        )+
    };
    ($Z3ty:ty, $tr:ident::$op:ident, $num:ty) => {
        impl $tr<$Z3ty> for $num {
            type Output = $Z3ty;
            fn $op(self, rhs: $Z3ty) -> Self::Output {
                let lhs = self.into_ast(&rhs);
                lhs.$op(&rhs)
            }
        }

        impl<'a> $tr<&'a $Z3ty> for $num {
            type Output = $Z3ty;
            fn $op(self, rhs: &'a $Z3ty) -> Self::Output {
                let lhs = self.into_ast(rhs);
                lhs.$op(rhs)
            }
        }
    };
}

impl_trait_number_types!(Int, Add::add, [u8, i8, u16, i16, u32, i32, u64, i64]);
impl_trait_number_types!(Int, Sub::sub, [u8, i8, u16, i16, u32, i32, u64, i64]);
impl_trait_number_types!(Int, Mul::mul, [u8, i8, u16, i16, u32, i32, u64, i64]);
impl_trait_number_types!(Int, Div::div, [u8, i8, u16, i16, u32, i32, u64, i64]);

impl_trait_number_types!(BV, Add::add, [u8, i8, u16, i16, u32, i32, u64, i64]);
impl_trait_number_types!(BV, Sub::sub, [u8, i8, u16, i16, u32, i32, u64, i64]);
impl_trait_number_types!(BV, Mul::mul, [u8, i8, u16, i16, u32, i32, u64, i64]);
impl_trait_number_types!(BV, BitXor::bitxor, [u8, i8, u16, i16, u32, i32, u64, i64]);
impl_trait_number_types!(BV, BitAnd::bitand, [u8, i8, u16, i16, u32, i32, u64, i64]);
impl_trait_number_types!(BV, BitOr::bitor, [u8, i8, u16, i16, u32, i32, u64, i64]);

macro_rules! integer_sum_product {
    ($zero:expr, $one:expr, $($a:ty)*) => ($(
        impl Sum for $a {
            fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
                iter.reduce(
                    |a, b| a + b,
                ).unwrap_or($zero)
            }
        }

        impl Product for $a {
            fn product<I: Iterator<Item=Self>>(iter: I) -> Self {
                iter.reduce(
                    |a, b| a * b,
                ).unwrap_or($one)
            }
        }

        impl<'a> Sum<&'a $a> for $a {
            fn sum<I: Iterator<Item=&'a Self>>(iter: I) -> Self {
                iter.cloned().reduce(
                    |a, b| a + b,
                ).unwrap_or($zero)
            }
        }

        impl<'a> Product<&'a $a> for $a {
            fn product<I: Iterator<Item=&'a Self>>(iter: I) -> Self {
                iter.cloned().reduce(
                    |a, b| a * b,
                ).unwrap_or($one)
            }
        }
    )*);
}

integer_sum_product!(Int::from_u64(0), Int::from_u64(1), Int);
integer_sum_product!(Real::from_rational(0, 1), Real::from_rational(1, 1), Real);
