use z3::ast;
use z3::datatype_builder::DatatypeAccessor;
use z3::*;

#[test]
fn test_datatype_accessor_constructors() {
    let _ = env_logger::try_init();

    // Ensure the convenience constructors produce the expected enum variants.
    let as_sort = DatatypeAccessor::sort(Sort::int());
    match as_sort {
        DatatypeAccessor::Sort(s) => {
            // A Sort::int() compared to itself should be equal.
            assert_eq!(s, Sort::int());
        }
        _ => panic!("Expected DatatypeAccessor::Sort variant"),
    }

    let as_datatype = DatatypeAccessor::datatype("SomeType");
    match as_datatype {
        DatatypeAccessor::Datatype(sym) => {
            // Symbol equality can be checked by converting to z3 symbol and comparing names.
            // We don't have a direct accessor for the string here, but constructing the same
            // symbol should compare equal at the Symbol level.
            assert_eq!(sym, "SomeType".into());
        }
        _ => panic!("Expected DatatypeAccessor::Datatype variant"),
    }
}

#[test]
fn test_create_datatypes_with_explicit_accessors_and_constructors() {
    let _ = env_logger::try_init();

    // This test builds two mutually-recursive datatypes (TreeX and ListX) using the
    // high-level DatatypeBuilder and DatatypeAccessor helpers, and exercises
    // constructors, testers and accessors via the solver.
    let tree_builder = DatatypeBuilder::new("TreeX")
        .variant("leaf", vec![("val", DatatypeAccessor::sort(Sort::int()))])
        .variant(
            "node",
            vec![("children", DatatypeAccessor::datatype("ListX"))],
        );

    let list_builder = DatatypeBuilder::new("ListX")
        .variant("nil", vec![])
        .variant(
            "cons",
            vec![
                ("car", DatatypeAccessor::datatype("TreeX")),
                ("cdr", DatatypeAccessor::datatype("ListX")),
            ],
        );

    let sorts = z3::datatype_builder::create_datatypes(vec![tree_builder, list_builder]);
    // Two sorts should be created.
    assert_eq!(sorts.len(), 2);

    let tree_sort = &sorts[0];
    let list_sort = &sorts[1];

    // Check expected numbers of variants and accessors
    assert_eq!(tree_sort.variants.len(), 2);
    assert_eq!(tree_sort.variants[0].accessors.len(), 1); // leaf.val
    assert_eq!(tree_sort.variants[1].accessors.len(), 1); // node.children

    assert_eq!(list_sort.variants.len(), 2);
    assert_eq!(list_sort.variants[0].accessors.len(), 0); // nil
    assert_eq!(list_sort.variants[1].accessors.len(), 2); // cons.car, cons.cdr

    // Use the constructors and accessors with a Solver.
    let solver = Solver::new();

    let ten = ast::Int::from_i64(10);
    let twenty = ast::Int::from_i64(20);

    // Create Tree.leaf(10) and Tree.leaf(20)
    let leaf_ten = tree_sort.variants[0].constructor.apply(&[&ten]);
    let leaf_twenty = tree_sort.variants[0].constructor.apply(&[&twenty]);

    // Create List.cons(leaf_twenty, nil)
    let nil = list_sort.variants[0].constructor.apply(&[]);
    let cons_twenty_nil = list_sort.variants[1]
        .constructor
        .apply(&[&leaf_twenty, &nil]);

    // Create List.cons(leaf_ten, cons_twenty_nil)
    let cons_ten_cons_twenty_nil = list_sort.variants[1]
        .constructor
        .apply(&[&leaf_ten, &cons_twenty_nil]);

    // Create Tree.node(cons_ten_cons_twenty_nil)
    let node = tree_sort.variants[1]
        .constructor
        .apply(&[&cons_ten_cons_twenty_nil]);

    // Assert that accessing children of node yields the list we constructed.
    let children = tree_sort.variants[1].accessors[0].apply(&[&node]);
    solver.assert(children.eq(&cons_ten_cons_twenty_nil));

    // Assert that the first element of that list (car) is leaf_ten
    let first = list_sort.variants[1].accessors[0].apply(&[&cons_ten_cons_twenty_nil]);
    solver.assert(first.eq(&leaf_ten));

    // Assert that accessing val from leaf_ten gives 10
    let val_from_leaf = tree_sort.variants[0].accessors[0]
        .apply(&[&leaf_ten])
        .as_int()
        .unwrap();
    solver.assert(val_from_leaf.eq(&ten));

    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
#[should_panic(expected = "At least one DatatypeBuilder must be specified")]
fn test_create_datatypes_empty_should_panic() {
    // create_datatypes asserts that at least one builder is provided.
    let _ = env_logger::try_init();
    let _ = z3::datatype_builder::create_datatypes(vec![]);
}
