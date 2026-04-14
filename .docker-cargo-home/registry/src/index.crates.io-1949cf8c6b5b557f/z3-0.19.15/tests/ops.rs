use num::abs;
use z3::{
    DeclKind, FuncDecl, SatResult, Solver, Sort, ast,
    ast::{Array, Ast, AstKind, BV, Bool, Dynamic, Float, Int, Real},
};

#[test]
fn test_bv_ops() {
    macro_rules! test_binary_op {
        ($op:tt) => {
            let a = BV::new_const("a", 5);
            let b = BV::new_const("b", 5);
            let _ = a $op b $op 2u64 $op 2i64;
        };
    }
    macro_rules! test_op_assign {
        ($op:tt, $assign:tt) => {
            test_binary_op!($op);
            let mut a = BV::new_const("a", 5);
            let b = BV::new_const("b", 5);
            a $assign b;
            a $assign 2u64;
            a $assign 2i64;
        };
    }
    macro_rules! test_unary_op {
        ($op:tt) => {
            let a = BV::new_const("a", 5);
            let _ = $op a;
        };
    }

    test_op_assign!(+, +=);
    test_op_assign!(-, -=);
    test_op_assign!(*, *=);
    test_op_assign!(&, &=);
    test_op_assign!(|, |=);
    test_op_assign!(^, ^=);
    test_op_assign!(<<, <<=);
    test_unary_op!(-);
    test_unary_op!(!);
}

#[test]
fn test_int_ops() {
    macro_rules! test_binary_op {
        ($op:tt) => {
            let a = Int::new_const("a");
            let b = Int::new_const("b");
            let _ = a $op b $op 2u64 $op 2i64;
        };
    }
    macro_rules! test_op_assign {
        ($op:tt, $assign:tt) => {
            test_binary_op!($op);
            let mut a = Int::new_const("a");
            let b = Int::new_const("b");
            a $assign b;
            a $assign 2u64;
            a $assign 2i64;
        };
    }
    macro_rules! test_unary_op {
        ($op:tt) => {
            let a = Int::new_const("a");
            let _ = $op a;
        };
    }

    test_op_assign!(+, +=);
    test_op_assign!(-, -=);
    test_op_assign!(*, *=);
    test_op_assign!(/, /=);
    test_op_assign!(%, %=);
    test_unary_op!(-);
}

#[test]
fn test_pow_ret_real() {
    let x = Int::new_const("x");
    let y = x.power(&x);
    assert!(y.get_sort() == Sort::real());
}

#[test]
fn test_real_ops() {
    macro_rules! test_binary_op {
        ($op:tt) => {
            let a = Real::new_const("a");
            let b = Real::new_const("b");
            let _ = a $op b;
        };
    }
    macro_rules! test_op_assign {
        ($op:tt, $assign:tt) => {
            test_binary_op!($op);
            let mut a = Real::new_const("a");
            let b = Real::new_const("b");
            a $assign b;
        };
    }
    macro_rules! test_unary_op {
        ($op:tt) => {
            let a = Real::new_const("a");
            let _ = $op a;
        };
    }

    test_op_assign!(+, +=);
    test_op_assign!(-, -=);
    test_op_assign!(*, *=);
    test_op_assign!(/, /=);
    test_unary_op!(-);
}

#[test]
fn test_float32_ops() {
    macro_rules! test_unary_op {
        ($op:tt) => {
            let a = Float::new_const_float32("a");
            let _ = $op a;
        };
    }
    test_unary_op!(-);

    let solver = Solver::new();

    // Infinite
    solver.check_assumptions(&[Float::from_f32(f32::INFINITY).is_infinite()]);
    solver.check_assumptions(&[Float::from_f32(f32::NEG_INFINITY).is_infinite()]);
    solver.check_assumptions(&[Float::from_f32(0f32).is_infinite().not()]);

    // Normal
    solver.check_assumptions(&[Float::from_f32(1f32).is_normal()]);
    solver.check_assumptions(&[Float::from_f32(f32::MIN_POSITIVE / 2.0).is_normal().not()]);

    // Subnormal
    solver.check_assumptions(&[Float::from_f32(f32::MIN_POSITIVE / 2.0).is_subnormal()]);
    solver.check_assumptions(&[Float::from_f32(1f32).is_subnormal().not()]);

    // Zero
    solver.check_assumptions(&[Float::from_f32(0f32).is_zero()]);
    solver.check_assumptions(&[Float::from_f32(1f32).is_zero().not()]);

    // NaN
    solver.check_assumptions(&[Float::from_f32(f32::NAN).is_nan()]);
    solver.check_assumptions(&[Float::from_f32(1f32).is_nan().not()]);
}

#[test]
fn test_double_ops() {
    macro_rules! test_unary_op {
        ($op:tt) => {
            let a = Float::new_const_double("a");
            let _ = $op a;
        };
    }
    test_unary_op!(-);

    let solver = Solver::new();

    // Infinite
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(f64::INFINITY).is_infinite()]),
        SatResult::Sat
    );
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(f64::NEG_INFINITY).is_infinite()]),
        SatResult::Sat
    );
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(0f64).is_infinite().not()]),
        SatResult::Sat
    );

    // Normal
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(1f64).is_normal()]),
        SatResult::Sat
    );
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(f64::MIN_POSITIVE / 2.0).is_normal().not()]),
        SatResult::Sat
    );

    // Subnormal
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(f64::MIN_POSITIVE / 2.0).is_subnormal()]),
        SatResult::Sat
    );
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(1f64).is_subnormal().not()]),
        SatResult::Sat
    );

    // Zero
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(0f64).is_zero()]),
        SatResult::Sat
    );
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(1f64).is_zero().not()]),
        SatResult::Sat
    );

    // NaN
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(f64::NAN).is_nan()]),
        SatResult::Sat
    );
    assert_eq!(
        solver.check_assumptions(&[Float::from_f64(1f64).is_nan().not()]),
        SatResult::Sat
    );
}

#[test]
fn test_bool_ops() {
    macro_rules! test_binary_op {
        ($op:tt) => {
            let a = Bool::new_const("a");
            let b = Bool::new_const("b");
            let _ = a $op b;
        };
    }
    macro_rules! test_op_assign {
        ($op:tt, $assign:tt) => {
            test_binary_op!($op);
            let mut a = Bool::new_const("a");
            let b = Bool::new_const("b");
            a $assign b;
        };
    }
    macro_rules! test_unary_op {
        ($op:tt) => {
            let a = Bool::new_const("a");
            let _ = $op a;
        };
    }

    test_op_assign!(&, &=);
    test_op_assign!(|, |=);
    test_op_assign!(^, ^=);
    test_unary_op!(!);
}

fn assert_bool_child(node: &impl Ast, idx: usize, expected: &Bool) {
    assert_eq!(&node.nth_child(idx).unwrap().as_bool().unwrap(), expected);
}

#[test]
fn test_ast_children() {
    let a = Bool::new_const("a");
    assert_eq!(a.num_children(), 0);
    assert_eq!(a.nth_child(0), None);
    assert_eq!(a.children().len(), 0);

    let not_a = a.not();
    assert_eq!(not_a.num_children(), 1);
    assert_bool_child(&not_a, 0, &a);
    assert_eq!(not_a.nth_child(1), None);

    let b = Bool::new_const("b");
    // This is specifically testing for an array of values, not an array of slices
    let a_or_b = Bool::or(&[a.clone(), b.clone()]);
    assert_eq!(a_or_b.num_children(), 2);
    assert_bool_child(&a_or_b, 0, &a);
    assert_bool_child(&a_or_b, 1, &b);
    assert_eq!(a_or_b.nth_child(2), None);
    let children = a_or_b.children();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0].as_bool().unwrap(), a);
    assert_eq!(children[1].as_bool().unwrap(), b);

    let c = Bool::new_const("c");
    let a_and_b_and_c = Bool::and(&[&a, &b, &c]);
    assert_eq!(a_and_b_and_c.num_children(), 3);
    assert_bool_child(&a_and_b_and_c, 0, &a);
    assert_bool_child(&a_and_b_and_c, 1, &b);
    assert_bool_child(&a_and_b_and_c, 2, &c);
    assert_eq!(a_and_b_and_c.nth_child(3), None);
    let children = a_and_b_and_c.children();
    assert_eq!(children[0].as_bool().unwrap(), a);
    assert_eq!(children[1].as_bool().unwrap(), b);
    assert_eq!(children[2].as_bool().unwrap(), c);
}

fn assert_ast_attributes<T: Ast>(expr: &T, is_const: bool) {
    assert_eq!(expr.kind(), AstKind::App);
    assert!(expr.is_app());
    assert_eq!(expr.is_const(), is_const);
}

#[test]
fn test_ast_attributes() {
    let a = Bool::new_const("a");
    let b = Bool::from_bool(false);
    let not_a = a.not();
    let a_or_b = &Bool::or(&[&a, &b]);
    assert_eq!(b.decl().kind(), DeclKind::FALSE);
    assert_eq!(not_a.decl().kind(), DeclKind::NOT);
    assert_eq!(a_or_b.decl().kind(), DeclKind::OR);

    assert_ast_attributes(&a, true);
    assert_ast_attributes(&b, true);
    assert_ast_attributes(&Dynamic::from_ast(&a), true);
    assert_ast_attributes(&not_a, false);
    assert_ast_attributes(a_or_b, false);

    assert_ast_attributes(&Array::new_const("arr", &Sort::int(), &Sort::bool()), true);
    assert_ast_attributes(&BV::new_const("bv", 512), true);
    assert_ast_attributes(&Real::new_const("r"), true);
    assert_ast_attributes(&ast::String::new_const("st"), true);

    let int_expr = Int::new_const("i");
    let set_expr = ast::Set::new_const("set", &Sort::int());
    assert_ast_attributes(&int_expr, true);
    assert_ast_attributes(&set_expr, true);
    assert_ast_attributes(&set_expr.add(&Dynamic::from_ast(&int_expr)), false);
}

#[test]
fn test_func_decl_attributes() {
    let const_decl = FuncDecl::new("c", &[], &Sort::bool());
    assert_eq!(const_decl.kind(), DeclKind::UNINTERPRETED);
    assert_eq!(const_decl.name(), "c");
    assert_eq!(const_decl.arity(), 0);

    let unary_decl = FuncDecl::new("unary", &[&Sort::bool()], &Sort::bool());
    assert_eq!(unary_decl.kind(), DeclKind::UNINTERPRETED);
    assert_eq!(unary_decl.name(), "unary");
    assert_eq!(unary_decl.arity(), 1);

    let binary_decl = FuncDecl::new("binary", &[&Sort::bool(), &Sort::bool()], &Sort::bool());
    assert_eq!(binary_decl.kind(), DeclKind::UNINTERPRETED);
    assert_eq!(binary_decl.name(), "binary");
    assert_eq!(binary_decl.arity(), 2);
}

#[test]
fn test_real_approx() {
    let x = Real::new_const("x");
    let xx = &x * &x;
    let zero = Real::from_rational(0, 1);
    let two = Real::from_rational(2, 1);
    let s = Solver::new();
    s.assert(x.ge(&zero));
    s.assert(xx.eq(&two));
    assert_eq!(s.check(), SatResult::Sat);
    let m = s.get_model().unwrap();
    let res = m.eval(&x, false).unwrap();
    assert_eq!(res.as_rational(), None); // sqrt is irrational
    println!("f64 res: {}", res.approx_f64());
    assert!((res.approx_f64() - ::std::f64::consts::SQRT_2).abs() < 1e-20);
    assert_eq!(res.approx(0), "1.");
    assert_eq!(res.approx(1), "1.4");
    assert_eq!(res.approx(2), "1.41");
    assert_eq!(res.approx(3), "1.414");
    assert_eq!(res.approx(4), "1.4142");
    assert_eq!(res.approx(5), "1.41421");
    assert_eq!(res.approx(6), "1.414213");
    assert_eq!(res.approx(7), "1.4142135");
    assert_eq!(res.approx(8), "1.41421356");
    assert_eq!(res.approx(9), "1.414213562");
    assert_eq!(res.approx(10), "1.4142135623");
    assert_eq!(res.approx(11), "1.41421356237");
    assert_eq!(res.approx(12), "1.414213562373");
    assert_eq!(res.approx(13), "1.4142135623730");
    assert_eq!(res.approx(14), "1.41421356237309");
    assert_eq!(res.approx(15), "1.414213562373095");
    assert_eq!(res.approx(16), "1.4142135623730950");
    assert_eq!(res.approx(17), "1.41421356237309504");
    assert_eq!(res.approx(18), "1.414213562373095048");
    assert_eq!(res.approx(19), "1.4142135623730950488");
    assert_eq!(res.approx(20), "1.41421356237309504880");
    assert_eq!(res.approx(21), "1.414213562373095048801");
    assert_eq!(res.approx(22), "1.4142135623730950488016");
    assert_eq!(res.approx(23), "1.41421356237309504880168");
    assert_eq!(res.approx(24), "1.414213562373095048801688");
    assert_eq!(res.approx(25), "1.4142135623730950488016887");
    assert_eq!(res.approx(26), "1.41421356237309504880168872");
    assert_eq!(res.approx(27), "1.414213562373095048801688724");
    assert_eq!(res.approx(28), "1.4142135623730950488016887242");
    assert_eq!(res.approx_f64(), res.approx(32).parse().unwrap());
    assert_ne!(res.approx_f64(), res.approx(16).parse().unwrap());
}

#[test]
fn into_ast_int() {
    let i = Int::from_u64(10);

    let a1 = &i + 1;
    let a2: Int = 1 + &i;
    assert_eq!(a1.simplify(), 11);
    assert_eq!(a2.simplify(), 11);

    let a1 = &i - 1;
    let a2: Int = 1 - &i;
    assert_eq!(a1.simplify(), 9);
    assert_eq!(a2.simplify(), -9);

    let a1 = &i * 2;
    let a2: Int = 2 * &i;
    assert_eq!(a1.simplify(), 20);
    assert_eq!(a2.simplify(), 20);

    let a1 = &i / 2;
    let a2: Int = 200 / &i;
    assert_eq!(a1.simplify(), 5);
    assert_eq!(a2.simplify(), 20);
}

#[test]
fn test_eq() {
    let t = Bool::from_bool(false);
    let t2 = Bool::from_bool(true);
    // the `true` here is being transparently converted
    // to a z3 Bool
    assert_eq!((t | t2).simplify(), Bool::from_bool(true));
}

#[test]
fn test_float_ops() {
    let t = Float::from_f64(10.0);
    assert!(abs(t.add_towards_zero(1.0).simplify().as_f64() - 11.0) < 0.1);
    assert!(abs(t.sub_towards_zero(1.0).simplify().as_f64() - 9.0) < 0.1);
    assert!(abs(t.mul_towards_zero(2.0).simplify().as_f64() - 20.0) < 0.1);
    assert!(abs(t.div_towards_zero(2.0).simplify().as_f64() - 5.0) < 0.1);
}

#[test]
fn test_int_sum() {
    // Test Sum for owned Int values
    let ints = vec![
        Int::from_i64(1),
        Int::from_i64(2),
        Int::from_i64(3),
        Int::from_i64(4),
        Int::from_i64(5),
    ];
    let sum: Int = ints.into_iter().sum();
    assert_eq!(sum.simplify(), 15);

    // Test Sum for borrowed Int values
    let ints = [Int::from_i64(10), Int::from_i64(20), Int::from_i64(30)];
    let sum: Int = ints.iter().sum();
    assert_eq!(sum.simplify(), 60);

    // Test empty iterator gives zero
    let empty: Vec<Int> = vec![];
    let sum: Int = empty.into_iter().sum();
    assert_eq!(sum, 0);

    // Test with symbolic values
    let x = Int::new_const("x");
    let y = Int::new_const("y");
    let z = Int::new_const("z");
    let ints = vec![x.clone(), y.clone(), z.clone()];
    let sum: Int = ints.into_iter().sum();
    // sum should be x + y + z
    let expected = &(&x + &y) + &z;
    assert_eq!(sum, expected);
}

#[test]
fn test_int_product() {
    // Test Product for owned Int values
    let ints = vec![Int::from_i64(2), Int::from_i64(3), Int::from_i64(4)];
    let product: Int = ints.into_iter().product();
    assert_eq!(product.simplify(), 24);

    // Test Product for borrowed Int values
    let ints = [Int::from_i64(5), Int::from_i64(6)];
    let product: Int = ints.iter().product();
    assert_eq!(product.simplify(), 30);

    // Test empty iterator gives one
    let empty: Vec<Int> = vec![];
    let product: Int = empty.into_iter().product();
    assert_eq!(product, 1);

    // Test with symbolic values
    let x = Int::new_const("x");
    let y = Int::new_const("y");
    let ints = vec![x.clone(), y.clone(), Int::from_i64(2)];
    let product: Int = ints.into_iter().product();
    // product should be x * y * 2
    let expected = &(&x * &y) * 2;
    assert_eq!(product, expected);
}

#[test]
fn test_real_sum() {
    // Test Sum for owned Real values
    let reals = vec![
        Real::from_rational(1, 2),
        Real::from_rational(1, 3),
        Real::from_rational(1, 6),
    ];
    let sum: Real = reals.into_iter().sum();
    assert_eq!(sum.simplify(), Real::from_rational(1, 1));

    // Test Sum for borrowed Real values
    let reals = [
        Real::from_rational(2, 1),
        Real::from_rational(3, 1),
        Real::from_rational(5, 1),
    ];
    let sum: Real = reals.iter().sum();
    assert_eq!(sum.simplify(), Real::from_rational(10, 1));

    // Test empty iterator gives zero
    let empty: Vec<Real> = vec![];
    let sum: Real = empty.into_iter().sum();
    assert_eq!(sum, Real::from_rational(0, 1));

    // Test with symbolic values
    let x = Real::new_const("x");
    let y = Real::new_const("y");
    let reals = vec![x.clone(), y.clone(), Real::from_rational(1, 1)];
    let sum: Real = reals.into_iter().sum();
    // sum should be x + y + 1
    let expected = &(&x + &y) + &Real::from_rational(1, 1);
    assert_eq!(sum, expected);
}

#[test]
fn test_real_product() {
    // Test Product for owned Real values
    let reals = vec![
        Real::from_rational(2, 1),
        Real::from_rational(3, 1),
        Real::from_rational(4, 1),
    ];
    let product: Real = reals.into_iter().product();
    assert_eq!(product.simplify(), Real::from_rational(24, 1));

    // Test Product for borrowed Real values
    let reals = [Real::from_rational(1, 2), Real::from_rational(1, 3)];
    let product: Real = reals.iter().product();
    assert_eq!(product.simplify(), Real::from_rational(1, 6));

    // Test empty iterator gives one
    let empty: Vec<Real> = vec![];
    let product: Real = empty.into_iter().product();
    assert_eq!(product, Real::from_rational(1, 1));

    // Test with symbolic values
    let x = Real::new_const("x");
    let y = Real::new_const("y");
    let reals = vec![x.clone(), y.clone(), Real::from_rational(2, 1)];
    let product: Real = reals.into_iter().product();
    // product should be x * y * 2
    let expected = &(&x * &y) * &Real::from_rational(2, 1);
    assert_eq!(product, expected);
}
