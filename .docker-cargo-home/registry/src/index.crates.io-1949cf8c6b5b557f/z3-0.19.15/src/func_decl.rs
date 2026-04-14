use std::convert::TryInto;
use std::ffi::CStr;
use std::fmt;
use std::{borrow::Borrow, ffi::c_uint};
use z3_sys::*;

use crate::{Context, FuncDecl, Sort, Symbol, Translate, ast, ast::Ast};
impl FuncDecl {
    pub(crate) unsafe fn wrap(ctx: &Context, z3_func_decl: Z3_func_decl) -> Self {
        unsafe {
            Z3_inc_ref(
                ctx.z3_ctx.0,
                Z3_func_decl_to_ast(ctx.z3_ctx.0, z3_func_decl).unwrap(),
            );
        }
        Self {
            ctx: ctx.clone(),
            z3_func_decl,
        }
    }

    pub fn new<S: Into<Symbol>>(name: S, domain: &[&Sort], range: &Sort) -> Self {
        let ctx = &Context::thread_local();
        assert!(domain.iter().all(|s| s.ctx.z3_ctx == ctx.z3_ctx));
        assert_eq!(ctx.z3_ctx, range.ctx.z3_ctx);

        let domain: Vec<_> = domain.iter().map(|s| s.z3_sort).collect();
        unsafe {
            Self::wrap(
                ctx,
                Z3_mk_func_decl(
                    ctx.z3_ctx.0,
                    name.into().as_z3_symbol(),
                    domain.len().try_into().unwrap(),
                    domain.as_ptr(),
                    range.z3_sort,
                )
                .unwrap(),
            )
        }
    }

    /// Create a partial order [`FuncDecl`] "Special Relation" over the given [`Sort`].
    ///
    /// The [`Sort`] may have many
    /// partial orders derived this way, distinguished by the second integer argument to this call,
    /// which represents the "id" of the partial order. Calling this twice with the same ID will
    /// yield the same partial order [`FuncDecl`].
    ///
    /// See <https://microsoft.github.io/z3guide/docs/theories/Special%20Relations/> for more info.
    ///
    /// A partial order is a binary relation that is reflexive, antisymmetric, and transitive.
    ///
    /// # Example
    ///
    /// ```
    /// # use z3::{FuncDecl, Sort, Solver, SatResult, Symbol};
    /// # use z3::ast::{Bool, Int};
    ///
    ///   let sort = Sort::int();
    ///   let partial_order = FuncDecl::partial_order(&sort, 0);
    ///   // Create a solver to assert properties of the partial order.
    ///   let solver = Solver::new();
    ///   let x = Int::new_const("x");
    ///   let y = Int::new_const("y");
    ///   let z = Int::new_const("z");
    ///
    ///   solver.assert(&partial_order.apply(&[&x, &x]).as_bool().unwrap());
    ///   // test reflexivity
    ///   assert_eq!(
    ///       solver.check_assumptions(&[partial_order.apply(&[&x, &x]).as_bool().unwrap().not()]),
    ///       SatResult::Unsat
    ///   );
    ///
    ///   // test antisymmetry
    ///   assert_eq!(
    ///       solver.check_assumptions(&[
    ///           partial_order.apply(&[&x, &y]).as_bool().unwrap(),
    ///           partial_order.apply(&[&y, &x]).as_bool().unwrap(),
    ///           x.eq(&y).not()
    ///       ]),
    ///       SatResult::Unsat
    ///   );
    ///
    ///   // test transitivity
    ///   assert_eq!(
    ///       solver.check_assumptions(&[
    ///           partial_order.apply(&[&x, &y]).as_bool().unwrap(),
    ///           partial_order.apply(&[&y, &z]).as_bool().unwrap(),
    ///           partial_order.apply(&[&x, &z]).as_bool().unwrap().not(),
    ///       ]),
    ///       SatResult::Unsat
    ///   );
    /// ```
    ///
    /// # See also
    ///
    /// - [`piecewise_linear_order`](Self::piecewise_linear_order)
    /// - [`linear_order`](Self::linear_order)
    /// - [`tree_order`](Self::tree_order)
    /// - [`transitive_closure`](Self::transitive_closure)
    pub fn partial_order<A: Borrow<Sort>>(a: A, id: usize) -> Self {
        let a = a.borrow();
        let ctx = &a.ctx;
        unsafe {
            Self::wrap(
                ctx,
                Z3_mk_partial_order(ctx.z3_ctx.0, a.z3_sort, id).unwrap(),
            )
        }
    }

    /// Create a piecewise linear order [`FuncDecl`] "Special Relation" over the given [`Sort`].
    ///
    /// See <https://microsoft.github.io/z3guide/docs/theories/Special%20Relations/> for more info.
    ///
    /// # See also
    ///
    /// - [`partial_order`](Self::partial_order)
    /// - [`linear_order`](Self::linear_order)
    /// - [`tree_order`](Self::tree_order)
    /// - [`transitive_closure`](Self::transitive_closure)
    pub fn piecewise_linear_order<A: Borrow<Sort>>(a: A, id: usize) -> Self {
        let a = a.borrow();
        let ctx = &a.ctx;
        unsafe {
            Self::wrap(
                ctx,
                Z3_mk_piecewise_linear_order(ctx.z3_ctx.0, a.z3_sort, id).unwrap(),
            )
        }
    }

    /// Create a linear order [`FuncDecl`] "Special Relation" over the given [`Sort`].
    ///
    /// See <https://microsoft.github.io/z3guide/docs/theories/Special%20Relations/> for more info.
    ///
    /// # See also
    ///
    /// - [`partial_order`](Self::partial_order)
    /// - [`piecewise_linear_order`](Self::piecewise_linear_order)
    /// - [`tree_order`](Self::tree_order)
    /// - [`transitive_closure`](Self::transitive_closure)
    pub fn linear_order<A: Borrow<Sort>>(a: A, id: usize) -> Self {
        let a = a.borrow();
        let ctx = &a.ctx;
        unsafe {
            Self::wrap(
                ctx,
                Z3_mk_linear_order(ctx.z3_ctx.0, a.z3_sort, id).unwrap(),
            )
        }
    }

    /// Create a tree order [`FuncDecl`] "Special Relation" over the given [`Sort`].
    ///
    /// See <https://microsoft.github.io/z3guide/docs/theories/Special%20Relations/> for more info.
    ///
    /// # See also
    ///
    /// - [`partial_order`](Self::partial_order)
    /// - [`piecewise_linear_order`](Self::piecewise_linear_order)
    /// - [`linear_order`](Self::linear_order)
    /// - [`transitive_closure`](Self::transitive_closure)
    pub fn tree_order<A: Borrow<Sort>>(a: A, id: usize) -> Self {
        let a = a.borrow();
        let ctx = &a.ctx;
        unsafe { Self::wrap(ctx, Z3_mk_tree_order(ctx.z3_ctx.0, a.z3_sort, id).unwrap()) }
    }

    /// Create a transitive closure [`FuncDecl`] "Special Relation" over the given [`FuncDecl`].
    ///
    /// See <https://microsoft.github.io/z3guide/docs/theories/Special%20Relations/> for more info.
    ///
    /// # See also
    ///
    /// - [`partial_order`](Self::partial_order)
    /// - [`piecewise_linear_order`](Self::piecewise_linear_order)
    /// - [`linear_order`](Self::linear_order)
    /// - [`tree_order`](Self::tree_order)
    pub fn transitive_closure<A: Borrow<FuncDecl>>(a: A) -> Self {
        let a = a.borrow();
        let ctx = &a.ctx;
        unsafe {
            Self::wrap(
                ctx,
                Z3_mk_transitive_closure(ctx.z3_ctx.0, a.z3_func_decl).unwrap(),
            )
        }
    }

    /// Return the number of arguments of a function declaration.
    ///
    /// If the function declaration is a constant, then the arity is `0`.
    ///
    /// ```
    /// # use z3::{Config, Context, FuncDecl, Solver, Sort, Symbol};
    /// let f = FuncDecl::new(
    ///     "f",
    ///     &[&Sort::int(), &Sort::real()],
    ///     &Sort::int());
    /// assert_eq!(f.arity(), 2);
    /// ```
    pub fn arity(&self) -> usize {
        unsafe { Z3_get_arity(self.ctx.z3_ctx.0, self.z3_func_decl) as usize }
    }

    /// Create a constant (if `args` has length 0) or function application (otherwise).
    ///
    /// Note that `args` should have the types corresponding to the `domain` of the `FuncDecl`.
    pub fn apply(&self, args: &[&dyn ast::Ast]) -> ast::Dynamic {
        assert!(args.iter().all(|s| s.get_ctx().z3_ctx == self.ctx.z3_ctx));

        let args: Vec<_> = args.iter().map(|a| a.get_z3_ast()).collect();

        unsafe {
            ast::Dynamic::wrap(&self.ctx, {
                Z3_mk_app(
                    self.ctx.z3_ctx.0,
                    self.z3_func_decl,
                    args.len().try_into().unwrap(),
                    args.as_ptr(),
                )
                .unwrap()
            })
        }
    }

    /// Return the `DeclKind` of this `FuncDecl`.
    pub fn kind(&self) -> DeclKind {
        unsafe { Z3_get_decl_kind(self.ctx.z3_ctx.0, self.z3_func_decl) }
    }

    /// Return the name of this `FuncDecl`.
    ///
    /// Strings will return the `Symbol`.  Ints will have a `"k!"` prepended to
    /// the `Symbol`.
    pub fn name(&self) -> String {
        unsafe {
            let z3_ctx = self.ctx.z3_ctx.0;
            let symbol = Z3_get_decl_name(z3_ctx, self.z3_func_decl).unwrap();
            match Z3_get_symbol_kind(z3_ctx, symbol) {
                SymbolKind::String => CStr::from_ptr(Z3_get_symbol_string(z3_ctx, symbol))
                    .to_string_lossy()
                    .into_owned(),
                SymbolKind::Int => format!("k!{}", Z3_get_symbol_int(z3_ctx, symbol)),
            }
        }
    }

    /// Returns the kind of the `i`-th domain (parameter) of this `FuncDecl`.
    ///
    /// Returns `None` if `i >= |domain|`.
    pub fn domain(&self, i: usize) -> Option<SortKind> {
        let z3_ctx = self.ctx.z3_ctx.0;
        let i = c_uint::try_from(i).unwrap();

        let domain_size = unsafe { Z3_get_domain_size(z3_ctx, self.z3_func_decl) };
        if i >= domain_size {
            return None;
        }

        Some(unsafe {
            Z3_get_sort_kind(
                z3_ctx,
                Z3_get_domain(z3_ctx, self.z3_func_decl, i).expect("cannot get domain of FuncDecl"),
            )
        })
    }

    /// Returns the kind of range (output) of this `FuncDecl`.
    pub fn range(&self) -> SortKind {
        let z3_ctx = self.ctx.z3_ctx.0;
        unsafe {
            Z3_get_sort_kind(
                z3_ctx,
                Z3_get_range(z3_ctx, self.z3_func_decl).expect("cannot get range of FuncDecl"),
            )
        }
    }
}

impl fmt::Display for FuncDecl {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let p = unsafe { Z3_func_decl_to_string(self.ctx.z3_ctx.0, self.z3_func_decl) };
        if p.is_null() {
            return Result::Err(fmt::Error);
        }
        match unsafe { CStr::from_ptr(p) }.to_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Result::Err(fmt::Error),
        }
    }
}

impl fmt::Debug for FuncDecl {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl Drop for FuncDecl {
    fn drop(&mut self) {
        unsafe {
            Z3_dec_ref(
                self.ctx.z3_ctx.0,
                Z3_func_decl_to_ast(self.ctx.z3_ctx.0, self.z3_func_decl).unwrap(),
            );
        }
    }
}

unsafe impl Translate for FuncDecl {
    fn translate(&self, dest: &Context) -> Self {
        unsafe {
            let func_decl_ast = Z3_func_decl_to_ast(self.ctx.z3_ctx.0, self.z3_func_decl).unwrap();
            let translated = Z3_translate(self.ctx.z3_ctx.0, func_decl_ast, dest.z3_ctx.0).unwrap();
            let func_decl = Z3_to_func_decl(self.ctx.z3_ctx.0, translated).unwrap();
            Self::wrap(dest, func_decl)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::ast::Bool;
    use crate::{Config, FuncDecl, PrepareSynchronized, Sort, with_z3_config};

    #[test]
    pub fn test_translate_func_decl() {
        let f = FuncDecl::new("foo", &[&Sort::bool()], &Sort::bool());
        let ff = f.synchronized();
        with_z3_config(&Config::new(), || {
            let f = ff.recover();
            assert_eq!(f.name(), "foo");
            assert_eq!(f.arity(), 1);
            assert!(f.apply(&[&Bool::from_bool(true)]).as_bool().is_some());
        });
    }
}
