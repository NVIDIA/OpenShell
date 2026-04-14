//! Helpers for building custom [datatype sorts](DatatypeSort).
//! The main entry point is [`create_datatypes`] which returns a
//! list of sorts(more than one for the case that you are defining a set of
//! mutually recursive data types)
//!
//!
//! # Example
//!
//! If you just want to define a single recursive datatype, you can do so with
//! the standard [`DatatypeBuilder`] as so.
//!
//! ```rust
//! use z3::{Sort, DatatypeAccessor, DatatypeBuilder, Symbol};
//! let dt = DatatypeBuilder::new("my_datatype")
//!     .variant("case1", vec![("field1", DatatypeAccessor::sort(Sort::int()))])
//!     .variant("case2", vec![("field2", DatatypeAccessor::datatype("my_datatype"))])
//!     .finish();
//! ```
//!
//! For mutually recursive types, you must use [`create_datatypes`]
//!
//! ```rust
//! use z3::{Sort, DatatypeAccessor, DatatypeBuilder, Symbol, datatype_builder::create_datatypes};
//! let my_tree = DatatypeBuilder::new("my_tree")
//!     .variant("leaf", vec![])
//!     .variant("node", vec![("children", DatatypeAccessor::datatype("my_list"))]);
//!
//! let my_list = DatatypeBuilder::new("my_list")
//!     .variant("nil", vec![])
//!     .variant("cons", vec![("hd", DatatypeAccessor::datatype("my_tree")), ("tl", DatatypeAccessor::datatype("my_list"))]);
//!
//! let dts = create_datatypes(vec![my_tree, my_list]);
//! ```
//!
mod constructor;

use std::convert::TryInto;
use z3_sys::*;

use crate::datatype_builder::constructor::{Constructor, ConstructorList};
use crate::{Context, DatatypeBuilder, DatatypeSort, DatatypeVariant, FuncDecl, Sort, Symbol};

impl DatatypeBuilder {
    pub fn new<S: Into<Symbol>>(name: S) -> Self {
        let ctx = &Context::thread_local();
        Self {
            ctx: ctx.clone(),
            name: name.into(),
            constructors: Vec::new(),
        }
    }

    pub fn variant(mut self, name: &str, fields: Vec<(&str, DatatypeAccessor)>) -> Self {
        let mut accessor_vec: Vec<(String, DatatypeAccessor)> = Vec::new();
        for (accessor_name, accessor) in fields {
            accessor_vec.push((accessor_name.to_string(), accessor));
        }

        self.constructors.push((name.to_string(), accessor_vec));

        self
    }

    pub fn finish(self) -> DatatypeSort {
        let mut dtypes = create_datatypes(vec![self]);
        dtypes.remove(0)
    }
}

/// Helper to build a single `DatatypeSort` from a raw Z3 sort and its builder.
fn build_datatype_sort(
    ctx: &Context,
    sort: Sort,
    datatype_builder: &DatatypeBuilder,
) -> DatatypeSort {
    let num_cs = datatype_builder.constructors.len();

    let mut variants: Vec<DatatypeVariant> = Vec::with_capacity(num_cs);

    for (j, (_cname, fs)) in datatype_builder.constructors.iter().enumerate() {
        let num_fs = fs.len();

        let raw_constructor = unsafe {
            Z3_get_datatype_sort_constructor(
                ctx.z3_ctx.0,
                sort.get_z3_sort(),
                j.try_into().unwrap(),
            )
            .unwrap()
        };
        let constructor: FuncDecl = unsafe { FuncDecl::wrap(ctx, raw_constructor) };

        let tester_func = unsafe {
            Z3_get_datatype_sort_recognizer(ctx.z3_ctx.0, sort.get_z3_sort(), j.try_into().unwrap())
                .unwrap()
        };
        let tester = unsafe { FuncDecl::wrap(ctx, tester_func) };

        let mut accessors: Vec<FuncDecl> = Vec::new();
        for k in 0..num_fs {
            let accessor_func = unsafe {
                Z3_get_datatype_sort_constructor_accessor(
                    ctx.z3_ctx.0,
                    sort.get_z3_sort(),
                    j.try_into().unwrap(),
                    k.try_into().unwrap(),
                )
                .unwrap()
            };

            accessors.push(unsafe { FuncDecl::wrap(ctx, accessor_func) });
        }

        variants.push(DatatypeVariant {
            constructor,
            tester,
            accessors,
        });
    }

    DatatypeSort { sort, variants }
}

pub fn create_datatypes(datatype_builders: Vec<DatatypeBuilder>) -> Vec<DatatypeSort> {
    let num = datatype_builders.len();
    assert!(num > 0, "At least one DatatypeBuilder must be specified");

    let ctx: Context = datatype_builders[0].ctx.clone();
    // Ensure all builders share the same context (should always be the case unless someone abused unsafe)
    assert!(datatype_builders.iter().all(|d| d.ctx == ctx));
    let mut names: Vec<Z3_symbol> = Vec::with_capacity(num);

    // Raw Z3 sorts to be filled by Z3_mk_datatypes
    let mut raw_sorts: Vec<Z3_sort> = Vec::with_capacity(num);

    // Use wrappers for constructors and constructor-lists so we don't have to
    // manually call Z3_del_constructor / Z3_del_constructor_list.
    let mut ctor_wrapped: Vec<Constructor> = Vec::with_capacity(num * 2);
    let mut clist_wrapped: Vec<ConstructorList> = Vec::with_capacity(num);

    for d in datatype_builders.iter() {
        names.push(d.name.as_z3_symbol());
        let num_cs = d.constructors.len();

        // Track where constructors for this datatype start within ctor_wrapped.
        let cs_start_idx = ctor_wrapped.len();

        for (cname, fs) in &d.constructors {
            let mut rname: String = "is-".to_string();
            rname.push_str(cname);

            let cname_symbol = Symbol::String(cname.clone());
            let rname_symbol = Symbol::String(rname);

            // Create the constructor using the higher-level helper which accepts
            // the same field representation used by `DatatypeBuilder`. That
            // helper will construct the temporary arrays required by the Z3 FFI.
            let ctor_wrapper = Constructor::new(
                &ctx,
                cname_symbol,
                rname_symbol,
                fs.as_slice(),
                &datatype_builders,
            );
            ctor_wrapped.push(ctor_wrapper);
        }

        assert!(ctor_wrapped.len() >= cs_start_idx + num_cs);

        // Build a `ConstructorList` from the constructors we just created.
        // The slice references constructors owned by `ctor_wrapped`, keeping
        // them alive for the duration of the call.
        let ctors_slice = &ctor_wrapped[cs_start_idx..cs_start_idx + num_cs];
        let clist_wrapper = ConstructorList::new(&ctx, ctors_slice);
        clist_wrapped.push(clist_wrapper);
    }

    assert_eq!(num, names.len());
    assert_eq!(num, clist_wrapped.len());

    // Prepare a temporary vector of raw constructor-list handles for the FFI
    // call. Keep it alive for the duration of the unsafe call.
    let mut clist_handles: Vec<Z3_constructor_list> = clist_wrapped
        .iter()
        .map(|c| c.z3_constructor_list())
        .collect();

    unsafe {
        Z3_mk_datatypes(
            ctx.z3_ctx.0,
            num.try_into().unwrap(),
            names.as_ptr(),
            raw_sorts.as_mut_ptr(),
            clist_handles.as_mut_ptr(),
        );
        raw_sorts.set_len(num);
    };
    let sorts = raw_sorts
        .into_iter()
        .map(|s| unsafe { Sort::wrap(&ctx, s) })
        .collect::<Vec<_>>();

    let mut datatype_sorts: Vec<DatatypeSort> = Vec::with_capacity(sorts.len());
    for (sort, datatype_builder) in sorts.into_iter().zip(&datatype_builders) {
        datatype_sorts.push(build_datatype_sort(&ctx, sort, datatype_builder));
    }

    // ctor_wrapped and clist_wrapped will be dropped here, calling the
    // appropriate Z3 deletion routines in their Drop impls. No manual calls
    // to Z3_del_constructor / Z3_del_constructor_list are required.
    datatype_sorts
}

/// Wrapper which can point to a sort (by value) or to a custom datatype (by name).
#[derive(Debug)]
pub enum DatatypeAccessor {
    Sort(Sort),
    Datatype(Symbol),
}

impl DatatypeAccessor {
    pub fn sort<S: Into<Sort>>(s: S) -> Self {
        Self::Sort(s.into())
    }

    pub fn datatype<S: Into<Symbol>>(s: S) -> Self {
        Self::Datatype(s.into())
    }
}
