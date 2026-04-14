use z3::ast::{Ast, Bool, Real};
use z3::quantifier_elimination::QuantifierElimination;
use z3::{AstVector, SatResult, Solver};

#[test]
fn lite_eliminates_existential_over_reals() {
    let x = Real::new_const("x");
    let y = Real::new_const("y");

    // formula: x > 0 ∧ x < y
    let x_gt_zero = x.gt(Real::from_rational(0, 1));
    let x_lt_y = x.lt(&y);
    let formula = Bool::and(&[&x_gt_zero, &x_lt_y]);

    let vars = AstVector::from(std::slice::from_ref(&x));
    let result = QuantifierElimination::lite(&vars, &formula);

    // After eliminating x the result should be satisfiable iff y > 0.
    // Check: result ∧ ¬(y > 0) must be unsat.
    let y_gt_zero = y.gt(Real::from_rational(0, 1));
    let solver = Solver::new();
    solver.assert(&result);
    solver.assert(y_gt_zero.not());
    assert_eq!(solver.check(), SatResult::Unsat);

    // And result alone must be sat.
    let solver2 = Solver::new();
    solver2.assert(&result);
    assert_eq!(solver2.check(), SatResult::Sat);
}

#[test]
fn model_project_eliminates_variable() {
    let x = Real::new_const("mp_x");
    let y = Real::new_const("mp_y");

    // formula: x > 0 ∧ x < y
    let x_gt_zero = x.gt(Real::from_rational(0, 1));
    let x_lt_y = x.lt(&y);
    let formula = Bool::and(&[&x_gt_zero, &x_lt_y]);

    // Obtain a concrete model satisfying the formula.
    let setup = Solver::new();
    setup.assert(&formula);
    assert_eq!(setup.check(), SatResult::Sat);
    let model = setup.get_model().unwrap();

    // Project x out using the model.
    let result = QuantifierElimination::model_project(&model, &[&x as &dyn Ast], &formula);

    // The result must be satisfiable — the model's assignment to y witnesses this.
    let solver = Solver::new();
    solver.assert(&result);
    assert_eq!(solver.check(), SatResult::Sat);

    // The projection ψ(y) must imply ∃x.(x>0 ∧ x<y), which is equivalent to y > 0.
    // So result ∧ ¬(y > 0) must be unsat.
    let solver2 = Solver::new();
    solver2.assert(&result);
    solver2.assert(y.gt(Real::from_rational(0, 1)).not());
    assert_eq!(solver2.check(), SatResult::Unsat);
}
