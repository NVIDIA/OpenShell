use crate::ast::Ast;
use crate::{Context, FuncDecl, Sort, Symbol};
use std::ffi::CString;
use z3_sys::*;

/// [`Ast`] node representing a datatype or enumeration value.
pub struct Datatype {
    pub(crate) ctx: Context,
    pub(crate) z3_ast: Z3_ast,
}

impl Datatype {
    pub fn new_const<S: Into<Symbol>>(name: S, sort: &Sort) -> Self {
        let ctx = &Context::thread_local();
        assert_eq!(ctx, &sort.ctx);
        assert_eq!(sort.kind(), SortKind::Datatype);

        unsafe {
            Self::wrap(ctx, {
                Z3_mk_const(ctx.z3_ctx.0, name.into().as_z3_symbol(), sort.z3_sort).unwrap()
            })
        }
    }

    pub fn fresh_const(prefix: &str, sort: &Sort) -> Self {
        let ctx = &Context::thread_local();
        assert_eq!(ctx, &sort.ctx);
        assert_eq!(sort.kind(), SortKind::Datatype);

        unsafe {
            Self::wrap(ctx, {
                let pp = CString::new(prefix).unwrap();
                let p = pp.as_ptr();
                Z3_mk_fresh_const(ctx.z3_ctx.0, p, sort.z3_sort).unwrap()
            })
        }
    }

    /// Update the field of the given datatype.
    ///
    /// The accessor should be taken from the datatype definition.
    pub fn update_field(&self, accessor: &FuncDecl, value: &impl Ast) -> Self {
        let c = self.ctx.get_z3_context();
        let field_access = accessor.z3_func_decl;
        let t = self.z3_ast;
        let v = value.get_z3_ast();

        // The Z3 docs say that the 1-indexed param should be a datatype,
        // but that seems like a typo.
        let domain = accessor.domain(0).expect("accessor lacks domain");
        assert_eq!(domain, SortKind::Datatype);

        let range = accessor.range();
        assert_eq!(value.get_sort().kind(), range);

        unsafe {
            Self::wrap(
                &self.ctx,
                Z3_datatype_update_field(c, field_access, t, v)
                    .expect("failed to update field of struct"),
            )
        }
    }
}
