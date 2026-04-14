use z3::ast::{Bool, Int};
use z3::*;

#[test]
fn test_optimize_get_assertions() {
    let _ = env_logger::try_init();

    let opt = Optimize::new();

    // Initially there should be no assertions.
    assert!(opt.get_assertions().is_empty());

    let x = Int::new_const("opt_x");

    // Hard assertions
    let a = x.eq(3);
    let b = x.eq(4);
    opt.assert(&a);
    opt.assert(&b);

    let assertions = opt.get_assertions();
    assert_eq!(assertions.len(), 2);
    assert!(assertions.contains(&a));
    assert!(assertions.contains(&b));

    // Soft assertions should NOT appear in get_assertions (they are objectives).
    opt.assert_soft(&x.eq(5), 10u32, None);
    let assertions_after_soft = opt.get_assertions();
    assert_eq!(
        assertions_after_soft.len(),
        2,
        "soft assertions should not be counted as hard assertions"
    );

    // assert_and_track should add a new assertion.
    // Verify the count increases by one and at least one returned
    // assertion is new compared to the previous list.
    let track_sym = Bool::new_const("opt_track_p");
    let c = x.eq(6);
    opt.assert_and_track(&c, &track_sym);

    let assertions_final = opt.get_assertions();
    assert_eq!(
        assertions_final.len(),
        assertions_after_soft.len() + 1,
        "assert_and_track should add one hard assertion"
    );

    // Ensure there is at least one assertion present now that wasn't present before.
    let added = assertions_final
        .iter()
        .any(|ast| !assertions_after_soft.contains(ast));
    assert!(
        added,
        "There should be at least one new assertion after assert_and_track"
    );
}
