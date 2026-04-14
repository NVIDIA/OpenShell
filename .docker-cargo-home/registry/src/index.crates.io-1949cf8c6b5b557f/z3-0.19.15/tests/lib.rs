use log::info;
use std::convert::TryInto;
use std::ops::Add;
use std::time::Duration;
use z3::ast::{Array, Ast, BV, Bool, Int, atleast, atmost};
use z3::*;

use num::{bigint::BigInt, rational::BigRational};
use std::str::FromStr;

mod algebraic_tests;
mod ast_vector_tests;
mod objectives;
mod ops;
mod quantifier_elimination_tests;
mod semver_tests;

#[test]
fn test_config() {
    let _ = env_logger::try_init();
    let mut c = Config::new();
    c.set_proof_generation(true);
}

#[test]
#[allow(deprecated)]
fn test_context() {
    let _ = env_logger::try_init();
    let mut cfg = Config::new();
    cfg.set_proof_generation(true);
    with_z3_config(&cfg, || {});
}

#[test]
fn test_fixedpoint_horn_clauses() {
    let _ = env_logger::try_init();

    let fp = Fixedpoint::new();
    let bool_sort = Sort::bool();

    // Three 0-ary predicates (propositions in the Horn clause system).
    let p_decl = FuncDecl::new("p", &[], &bool_sort);
    let q_decl = FuncDecl::new("q", &[], &bool_sort);
    let r_decl = FuncDecl::new("r", &[], &bool_sort);

    fp.register_relation(&p_decl);
    fp.register_relation(&q_decl);
    fp.register_relation(&r_decl);

    let p = p_decl.apply(&[]).as_bool().unwrap();
    let q = q_decl.apply(&[]).as_bool().unwrap();
    let r = r_decl.apply(&[]).as_bool().unwrap();

    // Rules: p => q, q => r
    fp.add_rule(&p.implies(&q), Some("p_to_q"));
    fp.add_rule(&q.implies(&r), Some("q_to_r"));
    // Fact: p is always true.
    fp.add_rule(&p, Some("fact_p"));

    // r is derivable via p => q => r.
    assert_eq!(fp.query(&r), SatResult::Sat);
}

#[test]
fn test_sorts_and_symbols() {
    let _ = env_logger::try_init();

    let _ = ast::Int::new_const("x");
    let _ = ast::Int::new_const("y");
}

#[test]
fn test_solving() {
    let _ = env_logger::try_init();

    let x = ast::Int::new_const("x");
    let y = ast::Int::new_const("y");

    let solver = Solver::new();
    solver.assert(x.gt(&y));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_solving_for_model() {
    let _ = env_logger::try_init();

    let x = ast::Int::new_const("x");
    let y = ast::Int::new_const("y");
    let zero = ast::Int::from_i64(0);
    let two = ast::Int::from_i64(2);
    let seven = ast::Int::from_i64(7);

    let solver = Solver::new();
    solver.assert(x.gt(&y));
    solver.assert(y.gt(&zero));
    solver.assert(y.rem(&seven).eq(&two));
    let x_plus_two = ast::Int::add(&[&x, &two]);
    solver.assert(x_plus_two.gt(&seven));
    assert_eq!(solver.check(), SatResult::Sat);

    let model = solver.get_model().unwrap();
    let xv = model.eval(&x, true).unwrap().as_i64().unwrap();
    let yv = model.eval(&y, true).unwrap().as_i64().unwrap();
    info!("x: {xv}");
    info!("y: {yv}");
    assert!(xv > yv);
    assert!(yv % 7 == 2);
    assert!(xv + 2 > 7);
}

#[test]
fn test_solving_for_model_cloned() {
    let _ = env_logger::try_init();

    let x = ast::Int::new_const("x");
    let y = ast::Int::new_const("y");
    let zero = ast::Int::from_i64(0);
    let two = ast::Int::from_i64(2);
    let seven = ast::Int::from_i64(7);

    let solver = Solver::new();
    solver.assert(x.gt(&y));
    solver.assert(y.gt(&zero));
    solver.assert(y.rem(&seven).eq(&two));
    let x_plus_two = ast::Int::add(&[&x, &two]);
    solver.assert(x_plus_two.gt(&seven));
    let cloned = solver.clone();
    assert_eq!(cloned.check(), SatResult::Sat);

    let model = cloned.get_model().unwrap();
    let xv = model.eval(&x, true).unwrap().as_i64().unwrap();
    let yv = model.eval(&y, true).unwrap().as_i64().unwrap();
    info!("x: {xv}");
    info!("y: {yv}");
    assert!(xv > yv);
    assert!(yv % 7 == 2);
    assert!(xv + 2 > 7);
}

#[test]
fn test_cloning_ast() {
    let _ = env_logger::try_init();

    let x = ast::Int::new_const("x");
    let y = x.clone();
    let zero = ast::Int::from_i64(0);

    let solver = Solver::new();
    solver.assert(x.eq(&zero));
    assert_eq!(solver.check(), SatResult::Sat);

    let model = solver.get_model().unwrap();
    let xv = model.eval(&x, true).unwrap().as_i64().unwrap();
    let yv = model.eval(&y, true).unwrap().as_i64().unwrap();
    assert_eq!(xv, 0);
    assert_eq!(yv, 0);
}

fn get_some_solver_assertions() -> Vec<ast::Bool> {
    let s = Solver::new();
    let x = ast::Int::new_const("x");
    let y = ast::Int::new_const("y");
    s.assert(x.gt(&y));
    s.get_assertions()
}

#[test]
fn test_solver_get_assertions_lifetime() {
    // This makes sure that the assertions created in the function
    // using the solver have the lifetime of the context rather
    // than the solver.
    let _ = env_logger::try_init();

    let assertions = get_some_solver_assertions();
    assert_eq!(assertions.len(), 1);
}

#[test]
fn test_format() {
    let ast = ast::Int::new_const("x");
    assert_eq!("x", format!("{ast}"));

    let int = Sort::int();
    assert_eq!("Int", format!("{int}"));
}

#[test]
fn test_bitvectors() {
    let a = ast::BV::new_const("a", 64);
    let b = ast::BV::new_const("b", 64);
    let two = ast::BV::from_i64(2, 64);

    let solver = Solver::new();
    solver.assert(a.bvsgt(&b));
    solver.assert(b.bvsgt(&two));
    let b_plus_two = b.bvadd(&two);
    solver.assert(b_plus_two.bvsgt(&a));
    assert_eq!(solver.check(), SatResult::Sat);

    let model = solver.get_model().unwrap();
    let av = model.eval(&a, true).unwrap().as_i64().unwrap();
    let bv = model.eval(&b, true).unwrap().as_i64().unwrap();
    assert!(av > bv);
    assert!(bv > 2);
    assert!(bv + 2 > av);
}

#[test]
fn test_bitvector_from_str() {
    let a = ast::BV::new_const("a", 129);
    // 2 ** 128
    let b = ast::BV::from_str(129, "340282366920938463463374607431768211456").unwrap();

    let solver = Solver::new();
    solver.assert(a.eq(&b));
    assert_eq!(solver.check(), SatResult::Sat);

    let model = solver.get_model().unwrap();
    let av = model.eval(&a, true).unwrap().to_string();
    assert_eq!(av, "#b100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string());
}

#[test]
fn test_floating_point_bits() {
    let float32 = ast::Float::new_const_float32("float32");
    let float64 = ast::Float::new_const_double("float64");
    let float128 = ast::Float::new_const("float128", 15, 113);
    let i = ast::Int::new_const("int");

    let exp32 = Sort::float_exponent_size(&float32.get_sort());
    let sig32 = Sort::float_significand_size(&float32.get_sort());
    let exp64 = Sort::float_exponent_size(&float64.get_sort());
    let sig64 = Sort::float_significand_size(&float64.get_sort());
    let exp128 = Sort::float_exponent_size(&float128.get_sort());
    let sig128 = Sort::float_significand_size(&float128.get_sort());
    let expi = Sort::float_exponent_size(&i.get_sort());
    let sigi = Sort::float_significand_size(&i.get_sort());

    assert!(exp32 == Some(8));
    assert!(sig32 == Some(24));
    assert!(exp64 == Some(11));
    assert!(sig64 == Some(53));
    assert!(exp128 == Some(15));
    assert!(sig128 == Some(113));
    assert!(expi.is_none());
    assert!(sigi.is_none());
}

#[test]
fn test_ast_translate() {
    let a = ast::Int::new_const("a");

    let dest_config = Config::default();
    let sync = a.synchronized();
    with_z3_config(&dest_config, move || {
        let translated_a = sync.recover();
        let slv = Solver::new();
        slv.assert(translated_a.eq(2));
        assert_eq!(slv.check(), SatResult::Sat);
        slv.assert(translated_a.eq(3));
        assert_eq!(slv.check(), SatResult::Unsat);
    });
}

#[test]
fn test_solver_new_from_smtlib2() {
    let problem = r#"
(declare-const x Real)
(declare-const y Real)
(declare-const z Real)
(assert (=( -(+(* 3 x) (* 2 y)) z) 1))
(assert (=(+( -(* 2 x) (* 2 y)) (* 4 z)) -2))
"#;
    let solver = Solver::new();
    solver.from_string(problem);
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_solver_to_smtlib2() {
    let solver1 = Solver::new();
    let t1 = ast::Bool::from_bool(true);
    let t2 = ast::Bool::from_bool(true);
    solver1.assert(t1.eq(&t2));
    let s1_smt2 = solver1.to_smt2();
    let solver2 = Solver::new();
    solver2.from_string(s1_smt2);
    assert_eq!(solver2.check(), solver1.check());
}

#[test]
fn test_solver_translate() {
    let a = ast::Int::new_const("a");
    let s = a.synchronized();
    let slv = with_z3_config(&Config::new(), || {
        let a = s.recover();
        let slv = Solver::new();
        slv.assert(a.eq(2));
        assert_eq!(slv.check(), SatResult::Sat);
        slv.synchronized()
    })
    .recover();
    slv.assert(a.eq(3));
    assert_eq!(slv.check(), SatResult::Unsat);
}

#[test]
fn test_model_translate() {
    let a = ast::Int::new_const("a");
    let slv = Solver::new();
    slv.assert(a.eq(2));
    assert_eq!(slv.check(), SatResult::Sat);

    let model = slv.get_model().unwrap();
    assert_eq!(2, model.eval(&a, true).unwrap().as_i64().unwrap());

    let model = model.synchronized();
    let a = a.synchronized();
    with_z3_config(&Config::new(), || {
        let translated_model = model.recover();
        let translated_a = a.recover();
        assert_eq!(
            2,
            translated_model
                .eval(&translated_a, true)
                .unwrap()
                .as_i64()
                .unwrap()
        );
    })
}

#[test]
fn test_pb_ops_model() {
    let x = ast::Bool::new_const("x");
    let y = ast::Bool::new_const("y");
    let solver = Solver::new();
    solver.push();

    solver.assert(ast::Bool::pb_eq(&[(&x, 1), (&y, 1)], 1));
    assert_eq!(solver.check(), SatResult::Sat);
    let model = solver.get_model().unwrap();
    let xv = model.eval(&x, true).unwrap().as_bool().unwrap();
    let yv = model.eval(&y, true).unwrap().as_bool().unwrap();
    info!("x: {xv}");
    info!("y: {yv}");
    assert!((xv && !yv) || (!xv && yv));

    solver.pop(1);
    solver.push();
    solver.assert(ast::Bool::pb_ge(&[(&x, 1), (&y, 1)], 2));
    assert_eq!(solver.check(), SatResult::Sat);
    let model = solver.get_model().unwrap();
    let xv = model.eval(&x, true).unwrap().as_bool().unwrap();
    let yv = model.eval(&y, true).unwrap().as_bool().unwrap();
    info!("x: {xv}");
    info!("y: {yv}");
    assert!(xv && yv);

    solver.pop(1);
    solver.assert(ast::Bool::pb_le(&[(&x, 1), (&y, 1)], 0));
    assert_eq!(solver.check(), SatResult::Sat);
    let model = solver.get_model().unwrap();
    let xv = model.eval(&x, true).unwrap().as_bool().unwrap();
    let yv = model.eval(&y, true).unwrap().as_bool().unwrap();
    info!("x: {xv}");
    info!("y: {yv}");
    assert!(!xv && !yv);
}

#[test]
fn function_ref_count() {
    let solver = Solver::new();

    let int_sort = Sort::int();

    let _f = FuncDecl::new("f", &[&int_sort], &int_sort);
    let _g = FuncDecl::new("g", &[&int_sort], &int_sort);

    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_params() {
    let _ = env_logger::try_init();

    let x = ast::Int::new_const("x");
    let y = ast::Int::new_const("y");

    let mut params = Params::new();
    params.set_bool("smt.mbqi", false);
    params.set_f64("smt.qi.eager_threshold", 5.0);
    params.set_u32("smt.qi.max_instances", 999);

    let solver = Solver::new();
    solver.set_params(&params);
    solver.assert(x.gt(&y));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_global_params() {
    let _ = env_logger::try_init();
    // could interfere with other tests if they use global params
    reset_all_global_params();
    let val = get_global_param("iDontExist");
    assert_eq!(val, None);
    let val = get_global_param("verbose");
    assert_eq!(val, Some("0".into()));
    set_global_param("verbose", "1");
    let val = get_global_param("verbose");
    assert_eq!(val, Some("1".into()));
    reset_all_global_params();
    let val = get_global_param("verbose");
    assert_eq!(val, Some("0".into()));
}

#[test]
fn test_substitution() {
    let x = ast::Real::new_const("x");
    let y = ast::Real::new_const("y");
    let z = ast::Real::new_const("z");

    let x_plus_y = ast::Real::add(&[&x, &y]);
    let x_plus_z = ast::Real::add(&[&x, &z]);

    let substitutions = &[(&y, &z)];

    assert!(x_plus_y.substitute(substitutions) == x_plus_z);
}

#[test]
fn test_real_cmp() {
    let solver = Solver::new();

    let x = ast::Real::new_const("x");
    let x_plus_1 = ast::Real::add(&[&x, &ast::Real::from_rational(1, 1)]);
    // forall x, x < x + 1
    let forall = ast::forall_const(&[&x], &[], &x.lt(&x_plus_1));

    solver.assert(&forall);
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_float() {
    let f = ast::Float::from_f64(1.0);
    assert_eq!(f.as_f64(), 1.0);
}

#[test]
fn test_float_add() {
    let solver = Solver::new();

    let x = ast::Float::new_const_float32("x");
    let x_plus_one = ast::RoundingMode::round_towards_zero().add(&x, 1.0f32);
    let y = ast::Float::from_f32(std::f32::consts::PI);

    solver.assert(x_plus_one.eq(y));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_arbitrary_size_real() {
    let solver = Solver::new();

    let x =
        ast::Real::from_rational_str("99999999999999999999998", "99999999999999999999999").unwrap();
    let y = ast::Real::from_rational(1, 1);

    solver.assert(x.lt(&y));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_arbitrary_size_int() {
    let solver = Solver::new();

    let x = ast::Int::from_str("99999999999999999999998").unwrap();
    let one = ast::Int::from_i64(1);
    let y = ast::Int::from_str("99999999999999999999999").unwrap();

    solver.assert(ast::Int::add(&[&x, &one]).eq(&y));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_arbitrary_size_real_from_bigrational() {
    let solver = Solver::new();

    let x =
        ast::Real::from_rational_str("99999999999999999999998", "99999999999999999999999").unwrap();
    let num = BigInt::from_str("99999999999999999999998").unwrap();
    let den = BigInt::from_str("99999999999999999999999").unwrap();
    let ratio = BigRational::new(num, den);

    solver.assert(x.eq(ratio));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_arbitrary_size_int_from_bigint() {
    let solver = Solver::new();

    let num1 = BigInt::from_str("99999999999999999999998").unwrap();
    let x = ast::Int::from_big_int(&num1);
    let y = ast::Int::from_i64(1);

    let num2 = BigInt::from_str("99999999999999999999999").unwrap();

    solver.assert(ast::Int::add(&[&x, &y]).eq(num2));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_string_eq() {
    let solver = Solver::new();

    let x = ast::String::from_str("foo").unwrap();
    let h = ast::String::new_const("h");

    solver.assert(x.eq("foo"));
    solver.assert(x.eq("bar").not());
    solver.assert(h.eq(&x));
    assert_eq!(solver.check(), SatResult::Sat);

    solver.assert(h.eq("bar"));
    assert_eq!(solver.check(), SatResult::Unsat);
}

#[test]
fn test_string_concat() {
    let solver = Solver::new();

    solver.assert(ast::String::concat(&["foo", "bar"]).eq("foobar"));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_string_prefix() {
    let solver = Solver::new();

    let x = ast::String::from_str("foo").unwrap();

    solver.assert(x.prefix("foobar"));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_string_suffix() {
    let solver = Solver::new();

    let x = ast::String::from_str("bar").unwrap();

    solver.assert(x.suffix("foobar"));
    assert_eq!(solver.check(), SatResult::Sat);
}

fn assert_string_roundtrip(source: &str) {
    let expr = ast::String::from_str(source).unwrap();
    assert_eq!(&expr.as_string().unwrap(), source);
}

#[test]
fn test_string_as_string() {
    assert_string_roundtrip("x");
    assert_string_roundtrip("'x'");
    assert_string_roundtrip(r#""x""#);
    assert_string_roundtrip(r#"\\"x\\""#);
}

#[test]
fn test_rec_func_def() {
    let _ = env_logger::try_init();

    let fac = RecFuncDecl::new("fac", &[&Sort::int()], &Sort::int());
    let n = ast::Int::new_const("n");
    let n_minus_1 = &n - 1;
    let fac_of_n_minus_1 = fac.apply(&[&n_minus_1]);
    let cond: ast::Bool = n.le(0);
    let body = cond.ite(
        &ast::Int::from_i64(1),
        &ast::Int::mul(&[&n, &fac_of_n_minus_1.as_int().unwrap()]),
    );

    fac.add_def(&[&n], &body);

    let x = ast::Int::new_const("x");
    let y = ast::Int::new_const("y");

    let solver = Solver::new();

    solver.assert(x.eq(fac.apply(&[&ast::Int::from_i64(4)]).as_int().unwrap()));
    solver.assert(y.eq(ast::Int::mul(&[&ast::Int::from_i64(5), &x])));
    solver.assert(y.eq(fac.apply(&[&ast::Int::from_i64(5)]).as_int().unwrap()));
    solver.assert(y.eq(120));

    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_rec_func_def_unsat() {
    let _ = env_logger::try_init();

    let fac = RecFuncDecl::new("fac", &[&Sort::int()], &Sort::int());
    let n = ast::Int::new_const("n");
    let n_minus_1 = ast::Int::sub(&[&n, &ast::Int::from_i64(1)]);
    let fac_of_n_minus_1 = fac.apply(&[&n_minus_1]);
    let cond: ast::Bool = n.le(0);
    let body = cond.ite(
        &ast::Int::from_i64(1),
        &ast::Int::mul(&[&n, &fac_of_n_minus_1.as_int().unwrap()]),
    );

    fac.add_def(&[&n], &body);

    let x = ast::Int::new_const("x");
    let y = ast::Int::new_const("y");

    let solver = Solver::new();

    solver.assert(x.eq(fac.apply(&[&ast::Int::from_i64(4)]).as_int().unwrap()));
    solver.assert(y.eq(ast::Int::mul(&[&ast::Int::from_i64(5), &x])));
    solver.assert(y.eq(fac.apply(&[&ast::Int::from_i64(5)]).as_int().unwrap()));

    // If fac was an uninterpreted function, this assertion would work.
    // To see this, comment out `fac.add_def(&[&n.into()], &body);`
    solver.assert(y.eq(25));

    assert_eq!(solver.check(), SatResult::Unsat);
}

#[test]
fn test_solver_unknown() {
    let _ = env_logger::try_init();
    let mut cfg = Config::new();
    // Use a very short timeout to quickly return "unknown"
    cfg.set_timeout_msec(1);
    with_z3_config(&cfg, || {
        // An open problem: find a model for x^3 + y^3 + z^3 == 42
        // See: https://en.wikipedia.org/wiki/Sums_of_three_cubes
        let x = ast::Int::new_const("x");
        let y = ast::Int::new_const("y");
        let z = ast::Int::new_const("z");
        let x_cube = ast::Int::mul(&[&x, &x, &x]);
        let y_cube = ast::Int::mul(&[&y, &y, &y]);
        let z_cube = ast::Int::mul(&[&z, &z, &z]);
        let sum_of_cubes = x_cube + y_cube + z_cube;
        let sum_of_cubes_is_42 = sum_of_cubes.eq(42);

        let solver = Solver::new();
        solver.assert(&sum_of_cubes_is_42);

        assert_eq!(solver.check(), SatResult::Unknown);
        assert!(solver.get_reason_unknown().is_some());
    });
}

#[test]
fn test_optimize_unknown() {
    let _ = env_logger::try_init();
    let mut cfg = Config::new();
    // Use a very short timeout to quickly return "unknown"
    cfg.set_timeout_msec(1);

    with_z3_config(&cfg, || {
        // An open problem: find a model for x^3 + y^3 + z^3 == 42
        // See: https://en.wikipedia.org/wiki/Sums_of_three_cubes
        let x = ast::Int::new_const("x");
        let y = ast::Int::new_const("y");
        let z = ast::Int::new_const("z");
        let x_cube = ast::Int::mul(&[&x, &x, &x]);
        let y_cube = ast::Int::mul(&[&y, &y, &y]);
        let z_cube = ast::Int::mul(&[&z, &z, &z]);
        let sum_of_cubes = x_cube + y_cube + z_cube;
        let sum_of_cubes_is_42 = sum_of_cubes.eq(42);

        let optimize = Optimize::new();
        optimize.assert(&sum_of_cubes_is_42);

        assert_eq!(optimize.check(&[]), SatResult::Unknown);
        assert!(optimize.get_reason_unknown().is_some());
    });
}

#[test]
fn test_optimize_new_from_smtlib2() {
    let _ = env_logger::try_init();

    let problem = r#"
(declare-const x Real)
(declare-const y Real)
(declare-const z Real)
(assert (=( -(+(* 3 x) (* 2 y)) z) 1))
(assert (=(+( -(* 2 x) (* 2 y)) (* 4 z)) -2))
"#;
    let optimize = Optimize::new();
    optimize.from_string(problem);
    assert_eq!(optimize.check(&[]), SatResult::Sat);
}

#[test]
fn test_get_unsat_core() {
    let _ = env_logger::try_init();

    let solver = Solver::new();

    assert!(
        solver.get_unsat_core().is_empty(),
        "no unsat core before assertions"
    );

    let x = ast::Int::new_const("x");

    let x_is_three = ast::Bool::new_const("x-is-three");
    solver.assert_and_track(x.eq(3), &x_is_three);

    let x_is_five = ast::Bool::new_const("x-is-five");
    solver.assert_and_track(x.eq(5), &x_is_five);

    assert!(
        solver.get_unsat_core().is_empty(),
        "no unsat core before checking"
    );

    let result = solver.check();
    assert_eq!(result, SatResult::Unsat);

    let unsat_core = solver.get_unsat_core();
    assert_eq!(unsat_core.len(), 2);
    assert!(unsat_core.contains(&x_is_three));
    assert!(unsat_core.contains(&x_is_five));
}

#[test]
fn test_optimize_get_unsat_core() {
    let _ = env_logger::try_init();

    let optimize = Optimize::new();

    assert!(
        optimize.get_unsat_core().is_empty(),
        "no unsat core before assertions"
    );

    let x = Int::new_const("x");

    let x_is_three = Bool::new_const("x-is-three");
    optimize.assert_and_track(&x.eq(3), &x_is_three);

    let x_is_five = Bool::new_const("x-is-five");
    optimize.assert_and_track(&x.eq(5), &x_is_five);

    assert!(
        optimize.get_unsat_core().is_empty(),
        "no unsat core before checking"
    );

    let result = optimize.check(&[]);
    assert_eq!(result, SatResult::Unsat);

    let unsat_core = optimize.get_unsat_core();
    assert_eq!(unsat_core.len(), 2);
    assert!(unsat_core.contains(&x_is_three));
    assert!(unsat_core.contains(&x_is_five));

    // try check API

    let a = x.eq(4);
    let b = x.eq(6);
    let result = optimize.check(&[a.clone(), b.clone()]);
    assert_eq!(result, SatResult::Unsat);

    let unsat_core = optimize.get_unsat_core();
    assert_eq!(unsat_core.len(), 2);
    assert!(unsat_core.contains(&a));
    assert!(unsat_core.contains(&b));
}

#[test]
fn test_datatype_builder() {
    let _ = env_logger::try_init();

    let solver = Solver::new();

    let maybe_int = DatatypeBuilder::new("MaybeInt")
        .variant("Nothing", vec![])
        .variant("Just", vec![("int", DatatypeAccessor::Sort(Sort::int()))])
        .finish();

    let nothing = maybe_int.variants[0].constructor.apply(&[]);
    let five = ast::Int::from_i64(5);
    let just_five = maybe_int.variants[1].constructor.apply(&[&five]);

    let nothing_is_nothing = maybe_int.variants[0]
        .tester
        .apply(&[&nothing])
        .as_bool()
        .unwrap();
    solver.assert(&nothing_is_nothing);

    let nothing_is_just = maybe_int.variants[1]
        .tester
        .apply(&[&nothing])
        .as_bool()
        .unwrap();
    solver.assert(nothing_is_just.not());

    let just_five_is_nothing = maybe_int.variants[0]
        .tester
        .apply(&[&just_five])
        .as_bool()
        .unwrap();
    solver.assert(just_five_is_nothing.not());

    let just_five_is_just = maybe_int.variants[1]
        .tester
        .apply(&[&just_five])
        .as_bool()
        .unwrap();
    solver.assert(&just_five_is_just);

    let five_two = maybe_int.variants[1].accessors[0]
        .apply(&[&just_five])
        .as_int()
        .unwrap();
    solver.assert(five.eq(&five_two));

    let four = ast::Int::from_i64(4);
    let just_four = just_five
        .as_datatype()
        .unwrap()
        .update_field(&maybe_int.variants[1].accessors[0], &four);
    let four_two = maybe_int.variants[1].accessors[0]
        .apply(&[&just_four])
        .as_int()
        .unwrap();
    solver.assert(four.eq(four_two));

    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_recursive_datatype() {
    let _ = env_logger::try_init();

    let solver = Solver::new();

    let list_sort = DatatypeBuilder::new("List")
        .variant("nil", vec![])
        .variant(
            "cons",
            vec![
                ("car", DatatypeAccessor::Sort(Sort::int())),
                ("cdr", DatatypeAccessor::Datatype("List".into())),
            ],
        )
        .finish();

    assert_eq!(list_sort.variants.len(), 2);
    let nil = list_sort.variants[0].constructor.apply(&[]);
    let five = ast::Int::from_i64(5);
    let cons_five_nil = list_sort.variants[1].constructor.apply(&[&five, &nil]);

    let nil_is_nil = list_sort.variants[0]
        .tester
        .apply(&[&nil])
        .as_bool()
        .unwrap();
    solver.assert(&nil_is_nil);

    let nil_is_cons = list_sort.variants[1]
        .tester
        .apply(&[&nil])
        .as_bool()
        .unwrap();
    solver.assert(nil_is_cons.not());

    let cons_five_nil_is_nil = list_sort.variants[0]
        .tester
        .apply(&[&cons_five_nil])
        .as_bool()
        .unwrap();
    solver.assert(cons_five_nil_is_nil.not());

    let cons_five_nil_is_cons = list_sort.variants[1]
        .tester
        .apply(&[&cons_five_nil])
        .as_bool()
        .unwrap();
    solver.assert(&cons_five_nil_is_cons);

    let car_cons_five_is_five = list_sort.variants[1].accessors[0]
        .apply(&[&cons_five_nil])
        .as_int()
        .unwrap();
    solver.assert(car_cons_five_is_five.eq(&five));
    assert_eq!(solver.check(), SatResult::Sat);

    let cdr_cons_five_is_nil = list_sort.variants[1].accessors[1]
        .apply(&[&cons_five_nil])
        .as_datatype()
        .unwrap();
    solver.assert(cdr_cons_five_is_nil.eq(nil.as_datatype().unwrap()));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_mutually_recursive_datatype() {
    let _ = env_logger::try_init();

    let solver = Solver::new();

    let tree_builder = DatatypeBuilder::new("Tree")
        .variant("leaf", vec![("val", DatatypeAccessor::Sort(Sort::int()))])
        .variant(
            "node",
            vec![("children", DatatypeAccessor::Datatype("TreeList".into()))],
        );

    let tree_list_builder = DatatypeBuilder::new("TreeList")
        .variant("nil", vec![])
        .variant(
            "cons",
            vec![
                ("car", DatatypeAccessor::Datatype("Tree".into())),
                ("cdr", DatatypeAccessor::Datatype("TreeList".into())),
            ],
        );

    let sorts = z3::datatype_builder::create_datatypes(vec![tree_builder, tree_list_builder]);
    assert_eq!(sorts.len(), 2);
    let tree_sort = &sorts[0];
    assert_eq!(tree_sort.variants.len(), 2);
    assert_eq!(tree_sort.variants[0].accessors.len(), 1);
    assert_eq!(tree_sort.variants[1].accessors.len(), 1);

    let tree_list_sort = &sorts[1];
    assert_eq!(tree_list_sort.variants.len(), 2);
    assert_eq!(tree_list_sort.variants[0].accessors.len(), 0);
    assert_eq!(tree_list_sort.variants[1].accessors.len(), 2);

    let ten = ast::Int::from_i64(10);
    let leaf_ten = tree_sort.variants[0].constructor.apply(&[&ten]);
    let leaf_ten_val_is_ten = tree_sort.variants[0].accessors[0]
        .apply(&[&leaf_ten])
        .as_int()
        .unwrap();
    solver.assert(leaf_ten_val_is_ten.eq(ten.clone()));
    assert_eq!(solver.check(), SatResult::Sat);

    let nil = tree_list_sort.variants[0].constructor.apply(&[]);
    let twenty = ast::Int::from_i64(20);
    let leaf_twenty = tree_sort.variants[0].constructor.apply(&[&twenty]);
    let cons_leaf_twenty_nil = tree_list_sort.variants[1]
        .constructor
        .apply(&[&leaf_twenty, &nil]);
    let cons_leaf_ten_cons_leaf_twenty_nil = tree_list_sort.variants[1]
        .constructor
        .apply(&[&leaf_ten, &cons_leaf_twenty_nil]);

    // n1 = Tree.node(TreeList.cons(Tree.leaf(10), TreeList.cons(Tree.leaf(20), TreeList.nil)))
    let n1 = tree_sort.variants[1]
        .constructor
        .apply(&[&cons_leaf_ten_cons_leaf_twenty_nil]);

    let n1_cons_nil = tree_list_sort.variants[1].constructor.apply(&[&n1, &nil]);
    // n2 = Tree.node(TreeList.cons(n1, TreeList.nil))
    let n2 = tree_sort.variants[1].constructor.apply(&[&n1_cons_nil]);

    solver.assert(n2.eq(&n1).not());

    // assert(TreeList.car(Tree.children(n2)) == n1)
    solver.assert(
        tree_list_sort.variants[1].accessors[0]
            .apply(&[&tree_sort.variants[1].accessors[0].apply(&[&n2])])
            .eq(&n1),
    );
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn get_model_without_check_does_not_exit() {
    let solver = Solver::new();
    solver.get_model();
}

#[test]
fn check_application_of_tactic_to_goal() {
    let params = Params::new();

    let tactic = Tactic::new("simplify");
    let repeat_tactic = Tactic::repeat(&tactic, 100);

    let goal = Goal::new(false, false, false);
    let x = ast::Bool::new_const("x");
    goal.assert(&x);

    let one = ast::Int::from_i64(1);
    let two = ast::Int::from_i64(2);

    let y = ast::Int::new_const("y");

    let y_plus_one_greater_than_or_equal_to_two = y.clone().add(&one).ge(&two);
    goal.assert(&y_plus_one_greater_than_or_equal_to_two);

    let y_greater_than_or_equal_to_one = y.ge(&one);
    goal.assert(&y_greater_than_or_equal_to_one);

    assert_eq!(
        format!("{goal}"),
        "(goal\n  x\n  (>= (+ y 1) 2)\n  (>= y 1))"
    );
    let apply_results = repeat_tactic.apply(&goal, Some(&params));
    let goal_results = apply_results
        .unwrap()
        .list_subgoals()
        .collect::<Vec<Goal>>();
    let goal_result = goal_results.first().unwrap();

    assert_eq!(format!("{goal_result}"), "(goal\n  x\n  (>= y 1))");
}

#[test]
fn test_goal_depth() {
    let goal = Goal::new(false, false, false);
    let a = ast::Bool::new_const("a");
    let b = ast::Bool::new_const("b");
    goal.assert(&a);
    goal.assert(&b);
    assert_eq!(goal.get_depth(), 0);
}

#[test]
fn test_goal_size() {
    let goal = Goal::new(false, false, false);
    let a = ast::Bool::new_const("a");
    let b = ast::Bool::new_const("b");
    goal.assert(&a);
    goal.assert(&b);
    assert_eq!(goal.get_size(), 2);
}

#[test]
fn test_goal_num_expr() {
    let goal = Goal::new(false, false, false);
    let a = ast::Bool::new_const("a");
    goal.assert(&a);
    assert_eq!(goal.get_num_expr(), 1);

    let goal = Goal::new(false, false, false);
    let a = ast::Bool::new_const("a");
    let b = ast::Bool::new_const("b");
    goal.assert(&a);
    goal.assert(&b);
    assert_eq!(goal.get_num_expr(), 2);
}

#[test]
fn test_goal_get_precision() {
    let false_bool = ast::Bool::from_bool(false);

    let goal = Goal::new(false, false, false);
    goal.assert(&false_bool);
    assert_eq!(goal.get_precision(), z3::GoalPrec::Precise);
}

#[test]
fn test_goal_is_inconsistent() {
    let false_bool = ast::Bool::from_bool(false);
    let goal = Goal::new(false, false, false);
    goal.assert(&false_bool);
    assert!(goal.is_inconsistent());

    let true_bool = ast::Bool::from_bool(true);
    let goal = Goal::new(false, false, false);
    goal.assert(&true_bool);
    assert!(!goal.is_inconsistent());
}

#[test]
fn test_goal_is_sat() {
    let false_bool = ast::Bool::from_bool(false);
    let goal = Goal::new(false, false, false);
    goal.assert(&false_bool);
    assert!(!goal.is_decided_sat());
    assert!(goal.is_decided_unsat());

    let true_bool = ast::Bool::from_bool(true);
    let goal = Goal::new(false, false, false);
    goal.assert(&true_bool);
    assert!(!goal.is_decided_unsat());
    assert!(goal.is_decided_sat());
}

#[test]
fn test_goal_reset() {
    let a = ast::Bool::new_const("a");
    let goal = Goal::new(false, false, false);
    goal.assert(&a);
    assert_eq!(format!("{goal}"), "(goal\n  a)");
    goal.reset();
    assert_eq!(format!("{goal}"), "(goal)");
}

#[test]
fn test_set_membership() {
    let _ = env_logger::try_init();

    let solver = Solver::new();
    let set = ast::Set::new_const("integer_set", &Sort::int());
    let one = ast::Int::from_u64(1);

    solver.push();
    solver.assert(set.eq(ast::Set::empty(&Sort::int())));

    solver.push();
    solver.assert(set.member(&one));
    // An empty set will never contain 1
    assert_eq!(solver.check(), SatResult::Unsat);
    solver.pop(1);

    solver.push();
    let set_with_one = set.add(&one);
    // Adding 1 to the empty set means it does now contain 1
    solver.assert(set_with_one.member(&one));
    assert_eq!(solver.check(), SatResult::Sat);
    let set_without_one = set_with_one.del(&one);
    // Removing 1 from the set means it no longer contains 1
    solver.assert(set_without_one.member(&one));
    assert_eq!(solver.check(), SatResult::Unsat);
    solver.pop(1);

    solver.push();
    let x = ast::Int::new_const("x");
    // An empty set will always return false for member
    let forall: ast::Bool = ast::forall_const(&[&x], &[], &set.member(&x).not());
    solver.assert(&forall);
    assert_eq!(solver.check(), SatResult::Sat);
    solver.pop(1);

    solver.pop(1);

    solver.push();
    // A singleton set of 1 will contain 1
    solver.assert(set.eq(ast::Set::empty(&Sort::int()).add(&one)));
    solver.assert(set.member(&one));
    assert_eq!(solver.check(), SatResult::Sat);
    solver.pop(1);
}

#[test]
fn test_dynamic_as_set() {
    let _ = env_logger::try_init();

    let set_sort = Sort::set(&Sort::int());
    let array_sort = Sort::array(&Sort::int(), &Sort::int());
    let array_of_sets = ast::Array::new_const("array_of_sets", &Sort::int(), &set_sort);
    let array_of_arrays = ast::Array::new_const("array_of_arrays", &Sort::int(), &array_sort);
    assert!(
        array_of_sets
            .select(&ast::Int::from_u64(0))
            .as_set()
            .is_some()
    );
    assert!(
        array_of_arrays
            .select(&ast::Int::from_u64(0))
            .as_set()
            .is_none()
    );
}

#[test]
fn test_array_store_select() {
    let _ = env_logger::try_init();

    let solver = Solver::new();
    let zero = ast::Int::from_u64(0);
    let one = ast::Int::from_u64(1);
    let set = ast::Array::new_const("integer_array", &Sort::int(), &Sort::int()).store(&zero, &one);

    solver.assert(set.select(&zero).eq(one).not());
    assert_eq!(solver.check(), SatResult::Unsat);
}

#[test]
fn test_goal_get_formulas() {
    let goal = Goal::new(false, false, false);
    let a = ast::Bool::new_const("a");
    let b = ast::Bool::new_const("b");
    let c = ast::Bool::new_const("c");
    goal.assert(&a);
    goal.assert(&b);
    goal.assert(&c);
    assert_eq!(goal.get_formulas(), vec![a, b, c],);
}

#[test]
fn test_tactic_skip() {
    let params = Params::new();

    let a = ast::Bool::new_const("a");
    let b = ast::Bool::new_const("b");
    let a_and_b_and_a = &a & &b & &a;
    let goal = Goal::new(false, false, false);
    goal.assert(&a_and_b_and_a);

    let tactic = Tactic::create_skip();
    let apply_results = tactic.apply(&goal, Some(&params));
    let goal_results = apply_results
        .unwrap()
        .list_subgoals()
        .collect::<Vec<Goal>>();
    let goal_result = goal_results.first().unwrap();
    assert_eq!(goal_result.get_formulas(), vec![a.clone(), b, a],);
}

#[test]
fn test_tactic_fail() {
    let params = Params::new();

    let a = ast::Bool::new_const("a");
    let goal = Goal::new(false, false, false);
    goal.assert(&a);

    let tactic = Tactic::new("fail");
    let apply_results = tactic.apply(&goal, Some(&params));
    assert!(apply_results.is_err());
}

#[test]
fn test_tactic_try_for() {
    let params = Params::new();

    let one = ast::Int::from_i64(1);
    let two = ast::Int::from_i64(2);
    let x = ast::Int::new_const("x");

    let goal = Goal::new(false, false, false);
    goal.assert(&x.ge(one.add(&two)));

    let tactic = Tactic::new("simplify");
    let try_for_tactic = tactic.try_for(Duration::from_secs(u64::MAX));

    // Test that `try_for` can successfully apply the underlying tactic
    let apply_results = try_for_tactic.apply(&goal, Some(&params));
    let goal_results = apply_results
        .unwrap()
        .list_subgoals()
        .collect::<Vec<Goal>>();
    let goal_result = goal_results.first().unwrap();
    assert_eq!(format!("{goal_result}"), "(goal\n  (>= x 3))");
}

#[test]
fn test_tactic_and_then() {
    let params = Params::new();

    let a = ast::Bool::new_const("a");
    let b = ast::Bool::new_const("b");
    let a_and_b_and_a = &a & &b & &a;
    let goal = Goal::new(false, false, false);
    goal.assert(&a_and_b_and_a);

    let tactic = Tactic::new("sat-preprocess");
    let and_then_tactic = tactic.and_then(&Tactic::new("simplify"));
    let apply_results = and_then_tactic.apply(&goal, Some(&params));
    let goal_results = apply_results
        .unwrap()
        .list_subgoals()
        .collect::<Vec<Goal>>();
    let goal_result = goal_results.first().unwrap();
    assert_eq!(goal_result.get_formulas(), vec![a, b]);
}

#[test]
fn test_tactic_or_else() {
    let params = Params::new();

    let a = ast::Bool::new_const("a");
    let b = ast::Bool::new_const("b");
    let a_and_b_and_a = &a & &b & &a;
    let goal = Goal::new(false, false, false);
    goal.assert(&a_and_b_and_a);

    let tactic = Tactic::new("sat-preprocess");
    let simplify = Tactic::new("simplify");
    let or_else_tactic = tactic.or_else(&simplify);
    let apply_results = or_else_tactic.apply(&goal, Some(&params));
    let goal_results = apply_results
        .unwrap()
        .list_subgoals()
        .collect::<Vec<Goal>>();
    let goal_result = goal_results.first().unwrap();
    assert_eq!(goal_result.get_formulas(), vec![a, b]);
}

#[test]
fn test_tactic_with() {
    let mut params = Params::new();
    params.set_u32("add_bound_lower", 1);
    params.set_u32("add_bound_upper", 1000);

    let x = ast::Int::new_const("x");

    let goal = Goal::new(false, false, false);
    goal.assert(&x.eq(&x));

    let tactic = Tactic::new("add-bounds").with(&params);

    // Test that `with` succesfully applied the parameter set
    let apply_results = tactic.apply(&goal, Some(&Params::new()));
    let goal_results = apply_results
        .unwrap()
        .list_subgoals()
        .collect::<Vec<Goal>>();
    let goal_result = goal_results.first().unwrap();
    assert_eq!(
        format!("{goal_result}"),
        "(goal\n  (= x x)\n  (<= x 1000)\n  (>= x 1))"
    );
}

#[test]
fn test_goal_apply_tactic() {
    pub fn test_apply_tactic(goal: Goal, before_formulas: Vec<Bool>, after_formulas: Vec<Bool>) {
        assert_eq!(goal.get_formulas(), before_formulas);
        let params = Params::new();

        let tactic = Tactic::new("sat-preprocess");
        let repeat_tactic = Tactic::repeat(&tactic, 100);
        let apply_results = repeat_tactic.apply(&goal, Some(&params));
        let goal_results = apply_results
            .unwrap()
            .list_subgoals()
            .collect::<Vec<Goal>>();
        let goal_result = goal_results.first().unwrap();
        assert_eq!(
            goal_result.get_formulas(),
            after_formulas,
            "Before: {before_formulas:?}"
        );
    }

    let a = ast::Bool::new_const("a");
    let b = ast::Bool::new_const("b");

    let a_and_b_and_a = &a & &b & &a;
    let goal = Goal::new(false, false, false);
    goal.assert(&a_and_b_and_a);
    test_apply_tactic(
        goal,
        vec![a.clone(), b.clone(), a.clone()],
        vec![a.clone(), b.clone()],
    );

    let a_implies_b = ast::Bool::implies(&a, &b).simplify();
    let a_and_a_implies_b = Bool::and(&[&a, &a_implies_b]);

    let goal = Goal::new(false, false, false);
    goal.assert(&a_and_a_implies_b);
    test_apply_tactic(
        goal,
        vec![a.clone(), a_implies_b.clone()],
        vec![a.clone(), b.clone()],
    );

    let goal = Goal::new(false, false, false);
    goal.assert(&a);
    goal.assert(&a_implies_b.clone());
    test_apply_tactic(
        goal,
        vec![a.clone(), a_implies_b.clone()],
        vec![a.clone(), b.clone()],
    );

    let false_bool = ast::Bool::from_bool(false);
    let goal = Goal::new(false, false, false);
    let true_and_false_and_true = ast::Bool::and(&[true, false, true].map(Bool::from_bool));
    goal.assert(&true_and_false_and_true);
    test_apply_tactic(goal, vec![false_bool.clone()], vec![false_bool.clone()]);
}

#[test]
fn test_tactic_cond() {
    let t1 = Tactic::new("qfnra");
    let t2 = Tactic::new("smt");
    let p = Probe::new("is-qfnra");

    let _t = Tactic::cond(&p, &t1, &t2);
}

#[test]
fn test_tactic_conditions() {
    let t1 = Tactic::new("qfnra");
    let t2 = Tactic::new("smt");
    let p = Probe::new("is-qfnra");

    t1.probe_or_else(&p, &t2);
    t1.when(&p);
    Tactic::cond(&p, &t1, &t2);
    Tactic::fail_if(&p);
}

#[test]
fn test_probe_debug() {
    let _v: Vec<String> = Probe::list_all().into_iter().map(|x| x.unwrap()).collect();
    assert_eq!(
        "A probe to give an upper bound of Ackermann congruence lemmas that a formula might generate.",
        Probe::describe("ackr-bound-probe").unwrap(),
    );
}

#[test]
fn test_probe_names() {
    let x = ast::Int::fresh_const("x");
    let g = Goal::new(false, false, false);

    g.assert(&x.gt(0));
    g.assert(&x.lt(10));
    g.assert(&x.lt(20));

    let num_consts_probe = Probe::new("num-consts");
    assert_eq!(1.0, num_consts_probe.apply(&g));

    let is_prop_probe = Probe::new("is-propositional");
    assert_eq!(0.0, is_prop_probe.apply(&g));

    let is_qflia_probe = Probe::new("is-qflia");
    assert_eq!(1.0, is_qflia_probe.apply(&g));
}

#[test]
fn test_probe_eq() {
    let two_probe = Probe::constant(2.0);
    let size_probe = Probe::new("size");
    let equals_two_probe = &size_probe.eq(&two_probe);

    let x = ast::Int::fresh_const("x");
    let g = Goal::new(false, false, false);
    g.assert(&x.gt(0));
    g.assert(&x.lt(10));
    assert_eq!(1.0, equals_two_probe.apply(&g));
}

#[test]
fn test_probe_gt() {
    let ten_probe = Probe::constant(10.0);
    let size_probe = Probe::new("size");
    let gt_ten_probe = &size_probe.gt(&ten_probe);

    let x = ast::Int::fresh_const("x");
    let g = Goal::new(false, false, false);
    g.assert(&x.gt(0));
    g.assert(&x.lt(10));
    assert_eq!(0.0, gt_ten_probe.apply(&g));
}

#[test]
fn test_probe_gte() {
    let two_probe = Probe::constant(2.0);
    let size_probe = Probe::new("size");
    let ge_two_probe = &size_probe.ge(&two_probe);

    let x = ast::Int::fresh_const("x");
    let g = Goal::new(false, false, false);
    g.assert(&x.gt(0));
    g.assert(&x.lt(10));
    assert_eq!(1.0, ge_two_probe.apply(&g));
}

#[test]
fn test_probe_le() {
    let two_probe = Probe::constant(2.0);
    let size_probe = Probe::new("size");
    let le_two_probe = &size_probe.le(&two_probe);

    let x = ast::Int::fresh_const("x");
    let g = Goal::new(false, false, false);
    g.assert(&x.gt(0));
    g.assert(&x.lt(10));
    assert_eq!(1.0, le_two_probe.apply(&g));
}

#[test]
fn test_probe_lt() {
    let ten_probe = Probe::constant(10.0);
    let size_probe = Probe::new("size");
    let le_ten_probe = &size_probe.le(&ten_probe);

    let x = ast::Int::fresh_const("x");
    let g = Goal::new(false, false, false);
    g.assert(&x.gt(0));
    g.assert(&x.lt(10));
    assert_eq!(1.0, le_ten_probe.apply(&g));
}

#[test]
fn test_probe_ne() {
    let two_probe = Probe::constant(2.0);
    let size_probe = Probe::new("size");
    let ne_two_probe = &size_probe.ne(&two_probe);

    let x = ast::Int::fresh_const("x");
    let g = Goal::new(false, false, false);
    g.assert(&x.gt(0));
    g.assert(&x.lt(10));
    assert_eq!(0.0, ne_two_probe.apply(&g));
}

#[test]
fn test_ast_safe_eq() {
    let x: ast::Dynamic = ast::Bool::new_const("a").into();
    let y: ast::Dynamic = ast::String::from_str("b").unwrap().into();

    let other_bool: ast::Dynamic = ast::Bool::new_const("c").into();
    let other_string: ast::Dynamic = ast::String::from_str("d").unwrap().into();

    let sd: SortDiffers = SortDiffers::new(other_bool.get_sort(), other_string.get_sort());

    let result = x.safe_eq(&y);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert_eq!(err.left(), sd.left());
    assert_eq!(err.right(), sd.right());
}

#[test]
fn test_ast_safe_decl() {
    let x: ast::Bool = ast::Bool::new_const("x");
    let x_not = x.not();
    assert_eq!(x_not.safe_decl().unwrap().kind(), DeclKind::NOT);

    let f = FuncDecl::new("f", &[&Sort::int()], &Sort::int());
    assert_eq!(f.domain(0), Some(SortKind::Int));
    assert_eq!(f.range(), SortKind::Int);

    let x = ast::Int::new_const("x");
    let f_x: ast::Int = f.apply(&[&x]).try_into().unwrap();
    let f_x_pattern: Pattern = Pattern::new(&[&f_x]);
    let forall = ast::forall_const(&[&x], &[&f_x_pattern], &x.eq(&f_x));
    assert!(forall.safe_decl().is_err());
    assert_eq!(
        format!("{}", forall.safe_decl().err().unwrap()),
        "ast node is not a function application, has kind Quantifier"
    );
}

//the intersection of "FOO"+"bar" and [a-z]+ is empty
#[test]
fn test_regex_capital_foobar_intersect_az_plus_is_unsat() {
    let solver = Solver::new();
    let s = ast::String::new_const("s");

    let re = ast::Regexp::intersect(&[
        &ast::Regexp::concat(&[&ast::Regexp::literal("FOO"), &ast::Regexp::literal("bar")]),
        &ast::Regexp::plus(&ast::Regexp::range(&'a', &'z')),
    ]);
    solver.assert(s.regex_matches(&re));
    assert!(solver.check() == SatResult::Unsat);
}

#[test]
fn test_regex_union() {
    let solver = Solver::new();
    let a = ast::String::from_str("a").unwrap();
    let b = ast::String::from_str("b").unwrap();
    let c = ast::String::from_str("c").unwrap();
    let re = ast::Regexp::union(&[ast::Regexp::literal("a"), ast::Regexp::literal("b")]);
    solver.assert(a.regex_matches(&re));
    solver.assert(b.regex_matches(&re));
    solver.assert(c.regex_matches(&re).not());
    assert!(solver.check() == SatResult::Sat);
}

#[test]
fn test_regex_union2() {
    let solver = Solver::new();
    let c = ast::String::from_str("c").unwrap();
    let re = ast::Regexp::union(&[ast::Regexp::literal("a"), ast::Regexp::literal("b")]);
    solver.assert(c.regex_matches(&re));
    assert!(solver.check() == SatResult::Unsat);
}

#[test]
/// <https://github.com/Z3Prover/z3/blob/21e59f7c6e5033006265fc6bc16e2c9f023db0e8/examples/dotnet/Program.cs#L329-L370>
fn test_array_example1() {
    let g = Goal::new(true, false, false);

    let aex = Array::new_const("MyArray", &Sort::int(), &Sort::bitvector(32));

    let sel = aex.select(&Int::from_u64(0));

    g.assert(&sel.eq(BV::from_u64(42, 32)));

    let xc = Int::new_const("x");

    let fd = FuncDecl::new("f", &[&Sort::int()], &Sort::int());

    let fapp = fd.apply(&[&xc as &dyn Ast]);

    g.assert(&Int::from_u64(123).eq(xc.clone().add(&fapp.as_int().unwrap())));

    let s = &Solver::new();
    for a in g.get_formulas() {
        s.assert(&a);
    }
    println!("Solver: {s}");

    let q = s.check();
    println!("Status: {q:?}");

    if q != SatResult::Sat {
        panic!("Solver did not return sat");
    }

    let model = s.get_model().unwrap();

    assert!(
        model.to_string()
            == "MyArray -> ((as const (Array Int (_ BitVec 32))) #x0000002a)\nx -> 0\nf -> {\n  123\n}\n"
    );

    assert!(
        model.get_const_interp(&aex).unwrap().to_string()
            == "((as const (Array Int (_ BitVec 32))) #x0000002a)"
    );

    assert!(model.get_const_interp(&xc).unwrap().to_string() == "0");

    assert!(model.get_func_interp(&fd).unwrap().to_string() == "[else -> 123]");
}

#[test]
/// <https://z3prover.github.io/api/html/classz3py_1_1_func_entry.html>
fn return_number_args_in_given_entry() {
    let f = FuncDecl::new("f", &[&Sort::int(), &Sort::int()], &Sort::int());

    let solver = Solver::new();
    solver.assert(
        f.apply(&[&Int::from_u64(0), &Int::from_u64(1)])
            .eq(Int::from_u64(10)),
    );
    solver.assert(
        f.apply(&[&Int::from_u64(1), &Int::from_u64(2)])
            .eq(Int::from_u64(20)),
    );
    solver.assert(
        f.apply(&[&Int::from_u64(1), &Int::from_u64(0)])
            .eq(Int::from_u64(10)),
    );

    assert!(solver.check() == SatResult::Sat);

    let model = solver.get_model().unwrap();
    let f_i = model.get_func_interp(&f).unwrap();
    assert!(f_i.get_num_entries() == 1);
    let e = &f_i.get_entries()[0];
    assert!(e.to_string() == "[1, 2, 20]");
    assert!(e.get_num_args() == 2);
    assert!(e.get_args()[0].to_string() == "1");
    assert!(e.get_args()[1].to_string() == "2");
    assert!(e.get_args().get(2).is_none());

    assert!(model.to_string() == "f -> {\n  1 2 -> 20\n  else -> 10\n}\n");
}

#[test]
/// <https://stackoverflow.com/questions/13395391/z3-finding-all-satisfying-models>
fn iterate_all_solutions() {
    let solver = Solver::new();
    let a = &Int::new_const("a");
    let b = &Int::new_const("b");
    let one = Int::from_u64(1);

    solver.assert(one.le(a));
    solver.assert(a.le(5));
    solver.assert(one.le(b));
    solver.assert(b.le(5));
    solver.assert(a.ge(&(2 * b)));

    let mut solutions = std::collections::HashSet::new();
    while solver.check() == SatResult::Sat {
        let model = solver.get_model().unwrap();
        let mut modifications = Vec::new();
        let this_solution = model
            .iter()
            .map(|fd| {
                modifications.push(
                    fd.apply(&[])
                        .eq(model.get_const_interp(&fd.apply(&[])).unwrap())
                        .not(),
                );
                format!(
                    "{} = {}",
                    fd.name(),
                    model.get_const_interp(&fd.apply(&[])).unwrap()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        solutions.insert(format!("[{this_solution}]"));
        solver.assert(Bool::or(&modifications.iter().collect::<Vec<_>>()));
    }

    assert!(
        solutions
            == vec![
                "[b = 1, a = 2]".to_string(),
                "[b = 2, a = 4]".to_string(),
                "[b = 1, a = 3]".to_string(),
                "[b = 2, a = 5]".to_string(),
                "[b = 1, a = 4]".to_string(),
                "[b = 1, a = 5]".to_string()
            ]
            .into_iter()
            .collect()
    );
}

#[test]
fn get_version() {
    println!("Z3 version: {:?}", z3::version());
    println!("Z3 full version string: {}", z3::full_version());
}

#[test]
fn test_consequences() {
    let solver = Solver::new();
    let a = Bool::new_const("a");
    let b = Bool::new_const("b");
    let c = Bool::new_const("c");
    let d = Bool::new_const("d");
    solver.assert(a.implies(&b));
    solver.assert(b.implies(&c));

    let assumptions = vec![a.clone()];
    let variables = vec![b.clone(), c.clone(), d.clone()];
    let mut cons = solver.get_consequences(&assumptions, &variables);
    assert!(cons.len() == 2);
    assert!(cons.pop().unwrap().to_string() == "(=> a c)");
    assert!(cons.pop().unwrap().to_string() == "(=> a b)");

    let assumptions = vec![c.not(), d.clone()];
    let variables = vec![a, b, c, d];
    let mut cons = solver.get_consequences(&assumptions, &variables);
    assert!(cons.len() == 4);
    assert!(cons.pop().unwrap().to_string() == "(=> (not c) (not a))");
    assert!(cons.pop().unwrap().to_string() == "(=> (not c) (not b))");
    assert!(cons.pop().unwrap().to_string() == "(=> (not c) (not c))");
    assert!(cons.pop().unwrap().to_string() == "(=> d d)");
}

#[test]
fn test_atmost() {
    let solver = Solver::new();
    let a = Bool::new_const("a");
    let b = Bool::new_const("b");
    let c = Bool::new_const("c");
    let d = Bool::new_const("d");
    solver.assert(a.implies(&b));
    solver.assert(b.implies(&c));

    solver.push();
    let am = atmost([&a, &b, &c, &d], 2);
    solver.assert(&am);
    assert!(matches!(solver.check(), SatResult::Sat));
    solver.pop(1);

    solver.push();
    solver.assert(&a);
    let am = atmost([&a, &b, &c, &d], 0);
    solver.assert(&am);
    assert!(matches!(solver.check(), SatResult::Unsat));
    solver.pop(1);
}

#[test]
fn test_atleast() {
    let solver = Solver::new();
    let a = Bool::new_const("a");
    let b = Bool::new_const("b");
    let c = Bool::new_const("c");
    let d = Bool::new_const("d");
    solver.assert(a.implies(&b));
    solver.assert(b.implies(&c));

    solver.push();
    let am = atleast([&a, &b, &c, &d], 4);
    solver.assert(&am);
    assert!(matches!(solver.check(), SatResult::Sat));
    solver.pop(1);

    solver.push();
    solver.assert(a.not());
    let am = atleast([&a, &b, &c, &d], 4);
    solver.assert(&am);
    assert!(matches!(solver.check(), SatResult::Unsat));
    solver.pop(1);
}

#[test]
fn test_model_iter() {
    let solver = Solver::new();

    let a = ast::Int::new_const("a");
    solver.assert(a.eq(2));
    solver.check();

    let model = solver.get_model().unwrap();

    // consume a model and return some asts constructed from it
    // this didn't compile before pr#324
    fn consume_model(model: Model) -> Vec<ast::Dynamic> {
        let mut asts = vec![];
        for func in &model {
            asts.push(func.apply(&[]));
        }
        asts
    }

    assert_eq!(
        consume_model(model),
        vec![ast::Dynamic::new_const("a", &Sort::int())]
    );
}

#[test]
fn test_round_towards_nearest_away() {
    let solver = Solver::new();

    let eps = f64::from_bits(0x3cb0000000000000);
    let x = z3::ast::Float::from_f64(1.0);
    let y = z3::ast::Float::from_f64(0.5 * eps);

    let rtna = z3::ast::RoundingMode::round_nearest_ties_to_away();
    let res_rtna = x.add_with_rounding_mode(y, &rtna);

    let expected = z3::ast::Float::from_f64(1.0000000000000002);
    solver.assert(res_rtna.eq(&expected));

    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_round_towards_nearest_even() {
    let solver = Solver::new();

    let eps = f64::from_bits(0x3cb0000000000000);
    let x = z3::ast::Float::from_f64(1.0);
    let y = z3::ast::Float::from_f64(0.5 * eps);

    let rtne = z3::ast::RoundingMode::round_nearest_ties_to_even();
    let res_rtne = x.add_with_rounding_mode(y, &rtne);

    let expected = z3::ast::Float::from_f64(1.0);
    solver.assert(res_rtne.eq(&expected));

    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_compare_trait_resolution() {
    let a = ast::Int::new_const("a");
    let b = ast::Int::new_const("b");
    let test_bool = Bool::new_const("test_bool");
    // ensure that we are returning `Bool`s here
    // the test here is that this compiles, if PartialEq
    // was being used, this would fail to compile
    assert!(!test_bool.eq(a.eq(&b)).is_const());
    assert!(!test_bool.eq(a.ne(&b)).is_const());
    assert!(!test_bool.ne(a.eq(&b)).is_const());
    assert!(!test_bool.ne(a.ne(&b)).is_const());
}
