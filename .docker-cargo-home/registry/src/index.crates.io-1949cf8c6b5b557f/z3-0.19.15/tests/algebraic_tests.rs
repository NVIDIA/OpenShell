use std::convert::TryFrom;
use z3::ast::{Algebraic, Ast, AstKind, Bool, Real};
use z3::{SatResult, Solver, Sort};

/// Build an `Algebraic` from a small rational.
/// Z3 recognises rational numerals as algebraic values.
fn alg(num: i64, den: i64) -> Algebraic {
    Algebraic::try_from(Real::from_rational(num, den))
        .expect("rational numeral is a valid algebraic value")
}

// ── is_value ──────────────────────────────────────────────────────────────────

#[test]
fn is_value_true_for_rational_numerals() {
    assert!(Algebraic::is_value(&Real::from_rational(1, 1)));
    assert!(Algebraic::is_value(&Real::from_rational(2, 1)));
    assert!(Algebraic::is_value(&Real::from_rational(1, 3)));
    assert!(Algebraic::is_value(&Real::from_rational(-7, 4)));
}

#[test]
fn is_value_false_for_symbolic_real() {
    assert!(!Algebraic::is_value(&Real::new_const("x")));
}

// ── TryFrom<Real> / From<Algebraic> ──────────────────────────────────────────

#[test]
fn try_from_rational_real_succeeds() {
    assert!(Algebraic::try_from(Real::from_rational(2, 1)).is_ok());
}

#[test]
fn try_from_symbolic_real_fails() {
    assert!(Algebraic::try_from(Real::new_const("x")).is_err());
}

#[test]
fn from_algebraic_widens_to_concrete_real() {
    // The widened Real wraps the same numeral, so as_rational still works.
    let r: Real = Real::from(alg(3, 2));
    assert!(r.as_rational().is_some());
}

#[test]
fn roundtrip_rational_through_real() {
    let a = alg(5, 4);
    let back = Algebraic::try_from(Real::from(a.clone())).unwrap();
    assert!(Algebraic::eq_algebraic(&a, &back));
}

// ── Sort and AST metadata ─────────────────────────────────────────────────────

#[test]
fn sort_of_rational_algebraic_is_real() {
    assert_eq!(alg(2, 1).get_sort(), Sort::real());
}

#[test]
fn sort_of_computed_algebraic_is_real() {
    // sqrt(2) is irrational but still lives in the Real sort.
    assert_eq!(alg(2, 1).root(2).get_sort(), Sort::real());
}

#[test]
fn sort_after_arithmetic_is_real() {
    let result = Algebraic::add(&alg(1, 1), &alg(2, 1));
    assert_eq!(result.get_sort(), Sort::real());
}

#[test]
fn rational_algebraic_has_numeral_kind() {
    // Rational numerals are Z3_NUMERAL_AST nodes.
    assert_eq!(alg(2, 1).kind(), AstKind::Numeral);
}

#[test]
fn all_algebraic_values_satisfy_is_app() {
    // is_app() returns true for both Numeral and App kinds.
    assert!(alg(2, 1).is_app());
    assert!(alg(2, 1).root(2).is_app());
}

#[test]
fn display_and_debug_produce_nonempty_strings() {
    let a = alg(2, 1);
    assert!(!format!("{a}").is_empty());
    assert!(!format!("{a:?}").is_empty());
    // Computed (irrational) algebraics also have a printable representation.
    let sqrt2 = alg(2, 1).root(2);
    assert!(!format!("{sqrt2}").is_empty());
}

#[test]
fn clone_produces_algebraically_equal_value() {
    let a = alg(7, 3);
    assert!(Algebraic::eq_algebraic(&a, &a.clone()));
}

// ── Sign predicates ───────────────────────────────────────────────────────────

#[test]
fn sign_of_positive() {
    let a = alg(3, 2);
    assert!(a.is_positive());
    assert!(!a.is_negative());
    assert!(!a.is_zero());
    assert_eq!(a.sign(), 1);
}

#[test]
fn sign_of_negative() {
    let a = alg(-1, 1);
    assert!(!a.is_positive());
    assert!(a.is_negative());
    assert!(!a.is_zero());
    assert_eq!(a.sign(), -1);
}

#[test]
fn sign_of_zero() {
    // Derive zero via subtraction to avoid relying on is_value for 0/1.
    let zero = Algebraic::sub(&alg(1, 1), &alg(1, 1));
    assert!(!zero.is_positive());
    assert!(!zero.is_negative());
    assert!(zero.is_zero());
    assert_eq!(zero.sign(), 0);
}

// ── Arithmetic ────────────────────────────────────────────────────────────────

#[test]
fn add() {
    let sum = Algebraic::add(&alg(1, 1), &alg(2, 1));
    assert!(Algebraic::eq_algebraic(&sum, &alg(3, 1)));
}

#[test]
fn sub() {
    let diff = Algebraic::sub(&alg(5, 1), &alg(3, 1));
    assert!(Algebraic::eq_algebraic(&diff, &alg(2, 1)));
}

#[test]
fn mul() {
    let product = Algebraic::mul(&alg(3, 1), &alg(4, 1));
    assert!(Algebraic::eq_algebraic(&product, &alg(12, 1)));
}

#[test]
fn div() {
    let quotient = Algebraic::div(&alg(6, 1), &alg(2, 1));
    assert!(Algebraic::eq_algebraic(&quotient, &alg(3, 1)));
}

#[test]
fn root_and_power_are_inverses() {
    let two = alg(2, 1);
    let back = two.root(2).power(2);
    assert!(Algebraic::eq_algebraic(&back, &two));
}

#[test]
fn cube_root_of_8_is_2() {
    assert!(Algebraic::eq_algebraic(&alg(8, 1).root(3), &alg(2, 1)));
}

#[test]
fn sqrt2_is_irrational() {
    let sqrt2 = alg(2, 1).root(2);
    assert!(!Algebraic::eq_algebraic(&sqrt2, &alg(1, 1)));
    assert!(!Algebraic::eq_algebraic(&sqrt2, &alg(7, 5))); // 1.4
    assert!(!Algebraic::eq_algebraic(&sqrt2, &alg(2, 1)));
}

// ── Comparisons ───────────────────────────────────────────────────────────────

#[test]
fn lt_and_gt() {
    let one = alg(1, 1);
    let two = alg(2, 1);
    assert!(Algebraic::lt(&one, &two));
    assert!(!Algebraic::lt(&two, &one));
    assert!(!Algebraic::lt(&one, &one));
    assert!(Algebraic::gt(&two, &one));
    assert!(!Algebraic::gt(&one, &two));
    assert!(!Algebraic::gt(&two, &two));
}

#[test]
fn sqrt2_lies_between_one_and_two() {
    let sqrt2 = alg(2, 1).root(2);
    assert!(Algebraic::gt(&sqrt2, &alg(1, 1)));
    assert!(Algebraic::lt(&sqrt2, &alg(2, 1)));
}

#[test]
fn eq_algebraic_reflexive_and_discriminating() {
    let a = alg(3, 2);
    let b = alg(3, 2);
    let c = alg(5, 2);
    assert!(Algebraic::eq_algebraic(&a, &b));
    assert!(!Algebraic::eq_algebraic(&a, &c));
}

// ── Ast::eq / Ast::ne return Bool constraints ─────────────────────────────────
//
// These are symbolic operations that build Z3 formula nodes, unlike the
// concrete bool returned by Algebraic::eq_algebraic / lt / gt.

#[test]
fn ast_eq_returns_satisfiable_bool_for_equal_values() {
    let constraint: Bool = alg(2, 1).eq(alg(2, 1));
    let solver = Solver::new();
    solver.assert(constraint);
    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn ast_ne_returns_satisfiable_bool_for_distinct_values() {
    let constraint: Bool = alg(1, 1).ne(alg(2, 1));
    let solver = Solver::new();
    solver.assert(constraint);
    assert_eq!(solver.check(), SatResult::Sat);
}

// ── Widening into symbolic expressions ────────────────────────────────────────

#[test]
fn widened_algebraic_used_as_symbolic_bound() {
    // Widen a computed algebraic (sqrt 2) to Real, then use it in a
    // symbolic constraint. This exercises the From<Algebraic> for Real path
    // and checks that the resulting Real is usable in Z3 formula building.
    let sqrt2: Real = Real::from(alg(2, 1).root(2));
    let x = Real::new_const("x");
    let solver = Solver::new();
    solver.assert(x.gt(&sqrt2));
    assert_eq!(solver.check(), SatResult::Sat);
}

#[ignore = "Fails when run with z3 4.8; likely an outdated upstream bug"]
#[test]
fn widened_algebraic_makes_constraint_unsat() {
    // x < sqrt(2) AND x >= sqrt(2) is unsatisfiable.
    let sqrt2: Real = Real::from(alg(2, 1).root(2));
    let x = Real::new_const("x");
    let solver = Solver::new();
    solver.assert(x.lt(&sqrt2));
    solver.assert(x.ge(&sqrt2));
    assert_eq!(solver.check(), SatResult::Unsat);
}

#[test]
fn solver_returns_algebraic_value_convertible_via_try_from() {
    // x² = 2, x > 0 forces Z3 to assign x = sqrt(2), which is returned as
    // a concrete algebraic value in the model and can be round-tripped back.
    let x = Real::new_const("x");
    let solver = Solver::new();
    solver.assert(Real::mul(&[&x, &x]).eq(Real::from_rational(2, 1)));
    solver.assert(x.gt(Real::from_rational(0, 1)));
    assert_eq!(solver.check(), SatResult::Sat);

    let model = solver.get_model().unwrap();
    let x_val = model.eval(&x, true).unwrap();
    let x_alg = Algebraic::try_from(x_val).unwrap();
    assert!(Algebraic::eq_algebraic(&x_alg, &alg(2, 1).root(2)));
}
