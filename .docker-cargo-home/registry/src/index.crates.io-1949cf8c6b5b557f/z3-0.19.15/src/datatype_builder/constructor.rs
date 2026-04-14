use z3_sys::{
    Z3_constructor, Z3_constructor_list, Z3_del_constructor, Z3_del_constructor_list,
    Z3_mk_constructor, Z3_mk_constructor_list, Z3_sort, Z3_symbol,
};

use super::DatatypeAccessor;
use crate::Context;
use crate::DatatypeBuilder;
use crate::Symbol;
use std::convert::TryInto;

/// Wrapper around a raw `Z3_constructor`.
pub struct Constructor {
    ctx: Context,
    z3_constructor: Z3_constructor,
}

impl Constructor {
    /// Create a wrapper around a raw `Z3_constructor`.
    pub unsafe fn wrap(ctx: &Context, z3_constructor: Z3_constructor) -> Self {
        Self {
            ctx: ctx.clone(),
            z3_constructor,
        }
    }

    /// Create a new constructor from high-level field descriptions.
    ///
    /// This function accepts the fields as a slice of `(String, DatatypeAccessor)`
    /// (the same representation used by `DatatypeBuilder`) and the full list
    /// of `DatatypeBuilder`s so that recursive references can be resolved to
    /// indices required by the Z3 API. The function constructs the temporary
    /// arrays required by `Z3_mk_constructor` internally.
    pub fn new(
        ctx: &Context,
        cname: Symbol,
        rname: Symbol,
        fields: &[(String, DatatypeAccessor)],
        all_builders: &[DatatypeBuilder],
    ) -> Self {
        let num_fs = fields.len();

        let mut field_names: Vec<Z3_symbol> = Vec::with_capacity(num_fs);
        let mut field_sorts: Vec<Option<Z3_sort>> = Vec::with_capacity(num_fs);
        let mut sort_refs: Vec<::std::os::raw::c_uint> = Vec::with_capacity(num_fs);

        for (fname, accessor) in fields {
            field_names.push(Symbol::String(fname.clone()).as_z3_symbol());
            match accessor {
                DatatypeAccessor::Datatype(dtype_name) => {
                    field_sorts.push(None);

                    let matching_names: Vec<_> = all_builders
                        .iter()
                        .enumerate()
                        .filter(|&(_, x)| &x.name == dtype_name)
                        .collect();

                    assert_eq!(
                        1,
                        matching_names.len(),
                        "One and only one occurrence of each datatype is expected.",
                    );

                    let (sort_ref, _) = matching_names[0];
                    sort_refs.push(sort_ref as u32);
                }
                DatatypeAccessor::Sort(sort) => {
                    field_sorts.push(Some(sort.z3_sort));
                    sort_refs.push(0);
                }
            }
        }

        let z3_constructor = unsafe {
            Z3_mk_constructor(
                ctx.z3_ctx.0,
                cname.as_z3_symbol(),
                rname.as_z3_symbol(),
                num_fs.try_into().unwrap(),
                field_names.as_ptr(),
                field_sorts.as_ptr(),
                sort_refs.as_mut_ptr(),
            )
        }
        .unwrap();

        unsafe { Self::wrap(ctx, z3_constructor) }
    }

    /// Access the underlying raw Z3 handle.
    pub fn z3_constructor(&self) -> Z3_constructor {
        self.z3_constructor
    }
}

impl Drop for Constructor {
    fn drop(&mut self) {
        unsafe {
            Z3_del_constructor(self.ctx.z3_ctx.0, self.z3_constructor);
        }
    }
}

/// Wrapper around a raw `Z3_constructor_list`.
pub struct ConstructorList {
    ctx: Context,
    z3_constructor_list: Z3_constructor_list,
}

impl ConstructorList {
    /// Create a wrapper around a raw `Z3_constructor_list`.
    pub unsafe fn wrap(ctx: &Context, z3_constructor_list: Z3_constructor_list) -> Self {
        Self {
            ctx: ctx.clone(),
            z3_constructor_list,
        }
    }

    /// Create a new Z3 constructor list via the FFI and wrap it.
    pub fn new(ctx: &Context, ctors: &[Constructor]) -> Self {
        let num_cs = ctors.len();
        // Build a temporary vector of raw constructor handles to pass to
        // `Z3_mk_constructor_list`. The underlying constructors are owned by
        // the `ctors` slice, which keeps them alive.
        let mut cs_handles: Vec<Z3_constructor> =
            ctors.iter().map(|c| c.z3_constructor()).collect();

        let z3_constructor_list = unsafe {
            Z3_mk_constructor_list(
                ctx.z3_ctx.0,
                num_cs.try_into().unwrap(),
                cs_handles.as_mut_ptr(),
            )
        }
        .unwrap();

        unsafe { Self::wrap(ctx, z3_constructor_list) }
    }

    /// Access the underlying raw Z3 handle.
    pub fn z3_constructor_list(&self) -> Z3_constructor_list {
        self.z3_constructor_list
    }
}

impl Drop for ConstructorList {
    fn drop(&mut self) {
        unsafe {
            Z3_del_constructor_list(self.ctx.z3_ctx.0, self.z3_constructor_list);
        }
    }
}
