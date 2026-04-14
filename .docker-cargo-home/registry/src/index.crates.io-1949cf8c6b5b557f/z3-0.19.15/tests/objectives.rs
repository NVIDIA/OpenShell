use z3::ast::Ast;
use z3::*;

#[test]
/// Given COUNT items with indices 0..COUNT,
/// find a function that reverses the indices with soft assertions.
///
/// An additional, incorrect soft assertion (COUNT-1 > 0) is used to
/// show that optimization incurred the least penalty by not
/// satisfying it.
fn test_optimize_assert_soft_and_get_objectives() {
    const COUNT: u64 = 10;

    let opt = Optimize::new();

    let int = Sort::int();
    let well_ordered_fn = FuncDecl::new("well_ordered_fn", &[&int], &int);

    // i < j in the order
    for i in 0..COUNT {
        opt.assert(&ast::Bool::and(&[
            &well_ordered_fn
                .apply(&[&ast::Int::from_u64(i)])
                .as_int()
                .unwrap()
                .lt(COUNT),
            &well_ordered_fn
                .apply(&[&ast::Int::from_u64(i)])
                .as_int()
                .unwrap()
                .ge(0),
        ]));
        for j in 0..i {
            opt.assert_soft(
                &well_ordered_fn
                    .apply(&[&ast::Int::from_u64(i)])
                    .as_int()
                    .unwrap()
                    .lt(well_ordered_fn
                        .apply(&[&ast::Int::from_u64(j)])
                        .as_int()
                        .unwrap()),
                1,
                None,
            );
        }
    }

    // incorrect assertion: COUNT-1 > 0
    opt.assert_soft(
        &well_ordered_fn
            .apply(&[&ast::Int::from_u64(0)])
            .as_int()
            .unwrap()
            .lt(well_ordered_fn
                .apply(&[&ast::Int::from_u64(COUNT - 1)])
                .as_int()
                .unwrap()),
        1,
        None,
    );

    assert_eq!(opt.check(&[]), SatResult::Sat);

    let model = opt.get_model().unwrap();

    for i in 0..COUNT {
        let i_new_pos = model
            .eval(&well_ordered_fn.apply(&[&ast::Int::from_u64(i)]), true)
            .unwrap()
            .as_int()
            .unwrap()
            .as_u64()
            .unwrap();
        for j in 0..i {
            let j_new_pos = model
                .eval(&well_ordered_fn.apply(&[&ast::Int::from_u64(j)]), true)
                .unwrap()
                .as_int()
                .unwrap()
                .as_u64()
                .unwrap();
            assert!(i_new_pos < j_new_pos);
        }
    }

    // the COUNT-1 > 0 assertion is not satisfied because doing so would incur
    // the penalty of all other soft assertions
    assert!(
        model
            .eval(&well_ordered_fn.apply(&[&ast::Int::from_u64(0)]), true)
            .unwrap()
            .as_int()
            .unwrap()
            .as_u64()
            .unwrap()
            > model
                .eval(
                    &well_ordered_fn.apply(&[&ast::Int::from_u64(COUNT - 1)]),
                    true
                )
                .unwrap()
                .as_int()
                .unwrap()
                .as_u64()
                .unwrap()
    );

    // There is a single objective containing soft constraints of the form:
    //
    // objective = (+ (ite (< (well_ordered_fn 1) (well_ordered_fn 0)) 0.0 1.0)
    // (ite (< (well_ordered_fn 2) (well_ordered_fn 0)) 0.0 1.0)
    // (ite (< (well_ordered_fn 2) (well_ordered_fn 1)) 0.0 1.0)
    // (ite (< (well_ordered_fn 3) (well_ordered_fn 0)) 0.0 1.0)
    // (ite (< (well_ordered_fn 3) (well_ordered_fn 1)) 0.0 1.0)
    // (ite (< (well_ordered_fn 3) (well_ordered_fn 2)) 0.0 1.0)
    // ...)
    let objectives = opt.get_objectives();
    assert_eq!(objectives.len(), 1);
    let objective = &objectives[0];
    dbg!(objective);
    assert_eq!(objective.get_sort(), Sort::real());
    assert_eq!(
        objective.num_children(),
        (0..COUNT).fold(0, |acc, i| acc + (0..i).count()) + 1
    );

    for ite in objective.children() {
        assert_eq!(ite.get_sort(), Sort::real());
        assert_eq!(ite.num_children(), 3);
        let ite_children = ite.children();
        let r#bool = &ite_children[0];

        assert_eq!(r#bool.num_children(), 2);
        for child in r#bool.children() {
            assert_eq!(child.get_sort(), Sort::int());
        }

        assert_eq!(
            ite_children[1].as_real().unwrap().as_rational().unwrap(),
            (0, 1)
        );
        assert_eq!(
            ite_children[2].as_real().unwrap().as_rational().unwrap(),
            (1, 1)
        );
    }
}
