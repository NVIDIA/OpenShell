use log::info;
use semver::{Version, VersionReq};
use std::collections::HashMap;
use z3::*;

struct Spec {
    vers: Version,
    reqs: HashMap<String, VersionReq>,
}

impl Spec {
    pub fn new(vers: &str, reqs: &[(&str, &str)]) -> Spec {
        let mut rs = HashMap::new();
        for &(p, r) in reqs {
            rs.insert(p.to_string(), VersionReq::parse(r).unwrap());
        }
        Spec {
            vers: Version::parse(vers).unwrap(),
            reqs: rs,
        }
    }
}

type SpecMap = HashMap<String, Vec<Spec>>;

fn get_version(sm: &SpecMap, pkg: &str, ver: usize) -> Option<Version> {
    sm.get(pkg).map(|specs| specs[ver].vers.clone())
}

fn first_version_req_index(sm: &SpecMap, pkg: &str, req: &VersionReq) -> Option<usize> {
    match sm.get(pkg) {
        None => None,
        Some(specs) => specs.iter().position(|spec| req.matches(&spec.vers)),
    }
}

fn last_version_req_index(sm: &SpecMap, pkg: &str, req: &VersionReq) -> Option<usize> {
    match sm.get(pkg) {
        None => None,
        Some(specs) => specs.iter().rposition(|spec| req.matches(&spec.vers)),
    }
}

#[test]
fn test_solve_simple_semver_example() {
    // This is a little example of solving version constraints the way cargo
    // might someday want to. It uses the optimizer portion of Z3.
    // see: https://github.com/rust-lang/cargo/issues/2064

    let _ = env_logger::try_init();

    let mut smap: SpecMap = HashMap::new();

    smap.insert(
        "postgres".to_string(),
        vec![
            ("0.1.0", &[]),
            ("0.1.1", &[]),
            ("0.1.2", &[]),
            ("0.1.3", &[]),
            ("0.2.0", &[]),
            ("0.2.1", &[]),
            ("0.2.2", &[]),
            ("0.2.3", &[]),
            ("0.2.4", &[]),
            ("0.3.0", &[]),
            ("0.4.0", &[]),
            ("0.4.1", &[]),
            ("0.4.2", &[]),
            ("0.4.3", &[]),
            ("0.4.4", &[]),
            ("0.4.5", &[]),
            ("0.4.6", &[]),
            ("0.5.0", &[]),
            ("0.5.1", &[]),
            ("0.5.2", &[]),
            ("0.5.3", &[]),
            ("0.5.4", &[]),
            ("0.5.5", &[]),
            ("0.5.6", &[]),
            ("0.6.0", &[]),
            ("0.6.1", &[]),
            ("0.6.2", &[]),
            ("0.6.3", &[]),
            ("0.6.4", &[]),
            ("0.6.5", &[]),
            ("0.7.0", &[]),
            ("0.7.1", &[]),
            ("0.7.2", &[]),
            ("0.7.2", &[]),
            ("0.7.3", &[]),
            ("0.7.4", &[]),
            ("0.7.5", &[]),
            ("0.8.0", &[]),
            ("0.8.1", &[]),
            ("0.8.2", &[]),
            ("0.8.3", &[]),
            ("0.8.4", &[]),
            ("0.8.5", &[]),
            ("0.8.6", &[]),
            ("0.8.7", &[]),
            ("0.8.8", &[]),
            ("0.8.9", &[]),
            ("0.9.0", &[]),
            ("0.9.1", &[]),
            ("0.9.2", &[]),
            ("0.9.3", &[]),
            ("0.9.4", &[]),
            ("0.9.5", &[]),
            ("0.9.6", &[]),
            ("0.10.0", &[]),
            ("0.10.1", &[]),
            ("0.10.2", &[]),
        ]
        .iter()
        .map(|&(v, r)| Spec::new(v, r))
        .collect(),
    );

    smap.insert(
        "r2d2-postgres".to_string(),
        vec![
            ("0.2.0", &[("postgres", "^0.2")]),
            ("0.2.1", &[("postgres", "^0.2")]),
            ("0.3.0", &[("postgres", "^0.4")]),
            ("0.3.1", &[("postgres", "^0.4")]),
            ("0.4.0", &[("postgres", "^0.5")]),
            ("0.5.0", &[("postgres", "^0.5")]),
            ("0.6.0", &[("postgres", "^0.6")]),
            ("0.7.0", &[("postgres", "^0.6")]),
            ("0.8.0", &[("postgres", "^0.7")]),
            ("0.9.0", &[("postgres", "^0.8")]),
            ("0.9.1", &[("postgres", "^0.9")]),
            ("0.9.2", &[("postgres", "^0.9")]),
            ("0.9.3", &[("postgres", "^0.10")]),
        ]
        .iter()
        .map(|&(v, r)| Spec::new(v, r))
        .collect(),
    );

    let opt = Optimize::new();

    let mut root: HashMap<String, VersionReq> = HashMap::new();
    let mut asts: HashMap<String, ast::Int> = HashMap::new();

    root.insert("postgres".to_string(), VersionReq::parse("0.9").unwrap());

    root.insert(
        "r2d2-postgres".to_string(),
        VersionReq::parse("0.9").unwrap(),
    );

    // Make a root Z3 Int constant for each pkg we're trying to solve for.
    for (k, v) in &root {
        let ast = ast::Int::fresh_const("root-pkg");
        info!("new AST for root {k}");

        match first_version_req_index(&smap, k, v) {
            None => (),
            Some(low) => {
                info!("Asserting: {k} >= #{low} (root)");
                opt.assert(&ast.ge(ast::Int::from_u64(low as u64)));
            }
        }
        match last_version_req_index(&smap, k, v) {
            None => (),
            Some(high) => {
                info!("Asserting: {k} <= #{high} (root)");
                opt.assert(&ast.le(ast::Int::from_u64(high as u64)));
            }
        }
        asts.insert(k.clone(), ast);
    }

    // Tell the optimizer to maximizes the sum of the root constants.
    opt.maximize(&ast::Int::add(
        &asts.values().collect::<Vec<&ast::Int>>()[..],
    ));

    // Ensure we have a constant for every pkg _or_ dep listed
    for k in (smap).keys() {
        asts.entry(k.clone()).or_insert_with(|| {
            info!("new AST for {k}");
            ast::Int::fresh_const("pkg")
        });
    }
    for specs in smap.values() {
        for spec in specs {
            for r in (spec).reqs.keys() {
                asts.entry(r.clone()).or_insert_with(|| {
                    info!("new AST for {r}");
                    ast::Int::fresh_const("dep-pkg")
                });
            }
        }
    }

    // Then assert all version constraints. Specifically: assert
    // an implication that whenever a package is of some version,
    // its required package is inside the acceptable range.
    for (k, specs) in &smap {
        let k_ast = &asts[k];
        for (n, spec) in (specs).iter().enumerate() {
            for (r, req) in &spec.reqs {
                let r_ast = &asts[r];
                match first_version_req_index(&smap, r, req) {
                    None => (),
                    Some(low) => {
                        info!(
                            "Asserting: {} == #{} {} => {} >= #{} {}",
                            k,
                            n,
                            get_version(&smap, k, n).unwrap(),
                            r,
                            low,
                            get_version(&smap, r, low).unwrap()
                        );
                        opt.assert(
                            &k_ast
                                .eq(ast::Int::from_u64(n as u64))
                                .implies(r_ast.ge(ast::Int::from_u64(low as u64))),
                        );
                    }
                }
                match last_version_req_index(&smap, r, req) {
                    None => (),
                    Some(high) => {
                        info!(
                            "Asserting: {} == #{} {} => {} <= #{} {}",
                            k,
                            n,
                            get_version(&smap, k, n).unwrap(),
                            r,
                            high,
                            get_version(&smap, r, high).unwrap()
                        );
                        opt.assert(
                            &k_ast
                                .eq(ast::Int::from_u64(n as u64))
                                .implies(r_ast.le(ast::Int::from_u64(high as u64))),
                        );
                    }
                }
            }
        }
    }

    assert_eq!(opt.check(&[]), SatResult::Sat);
    let model = opt.get_model().unwrap();

    for k in root.keys() {
        let ast = &asts[k];
        let idx = model.eval(ast, true).unwrap().as_i64().unwrap();
        info!(
            "solved: {}: #{} = {}",
            k,
            idx,
            get_version(&smap, k, idx as usize).unwrap()
        );
    }

    let pg_a = &asts["postgres"];
    let r2_a = &asts["r2d2-postgres"];

    let pg_v = model.eval(pg_a, true).unwrap().as_i64().unwrap() as usize;
    let r2_v = model.eval(r2_a, true).unwrap().as_i64().unwrap() as usize;

    assert_eq!(
        get_version(&smap, "postgres", pg_v).unwrap(),
        Version::parse("0.9.6").unwrap()
    );

    assert_eq!(
        get_version(&smap, "r2d2-postgres", r2_v).unwrap(),
        Version::parse("0.9.2").unwrap()
    );
}
