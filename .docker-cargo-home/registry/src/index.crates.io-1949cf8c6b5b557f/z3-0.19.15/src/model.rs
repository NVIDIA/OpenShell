use std::fmt;
use std::{ffi::CStr, iter::FusedIterator};
use z3_sys::*;

use crate::{
    AstVector, Context, FuncDecl, FuncInterp, Model, Optimize, Solver, Sort, Translate, ast::Ast,
};

impl Model {
    unsafe fn wrap(ctx: &Context, z3_mdl: Z3_model) -> Model {
        unsafe {
            Z3_model_inc_ref(ctx.z3_ctx.0, z3_mdl);
        }
        Model {
            ctx: ctx.clone(),
            z3_mdl,
        }
    }

    pub fn of_solver(slv: &Solver) -> Option<Model> {
        unsafe {
            let m = Z3_solver_get_model(slv.ctx.z3_ctx.0, slv.z3_slv);
            Some(Self::wrap(&slv.ctx, m?))
        }
    }

    pub fn of_optimize(opt: &Optimize) -> Option<Model> {
        unsafe {
            let m = Z3_optimize_get_model(opt.ctx.z3_ctx.0, opt.z3_opt);
            Some(Self::wrap(&opt.ctx, m?))
        }
    }

    /// Returns the interpretation of the given `ast` in the `Model`
    /// Returns `None` if there is no interpretation in the `Model`
    pub fn get_const_interp<T: Ast>(&self, ast: &T) -> Option<T> {
        let func = ast.safe_decl().ok()?;

        let ret =
            unsafe { Z3_model_get_const_interp(self.ctx.z3_ctx.0, self.z3_mdl, func.z3_func_decl) };
        Some(unsafe { T::wrap(&self.ctx, ret?) })
    }

    /// Returns the interpretation of the given `f` in the `Model`
    /// Returns `None` if there is no interpretation in the `Model`
    pub fn get_func_interp(&self, f: &FuncDecl) -> Option<FuncInterp> {
        if f.arity() == 0 {
            let ret = unsafe {
                Z3_model_get_const_interp(self.ctx.z3_ctx.0, self.z3_mdl, f.z3_func_decl)
            }?;
            let sort_kind = unsafe {
                Z3_get_sort_kind(
                    self.ctx.z3_ctx.0,
                    Z3_get_range(self.ctx.z3_ctx.0, f.z3_func_decl).unwrap(),
                )
            };
            match sort_kind {
                SortKind::Array => {
                    if unsafe { Z3_is_as_array(self.ctx.z3_ctx.0, ret) } {
                        let fd = unsafe {
                            FuncDecl::wrap(
                                &self.ctx,
                                Z3_get_as_array_func_decl(self.ctx.z3_ctx.0, ret).unwrap(),
                            )
                        };
                        self.get_func_interp(&fd)
                    } else {
                        None
                    }
                }
                _ => None,
            }
        } else {
            let ret =
                unsafe { Z3_model_get_func_interp(self.ctx.z3_ctx.0, self.z3_mdl, f.z3_func_decl) };
            Some(unsafe { FuncInterp::wrap(&self.ctx, ret?) })
        }
    }

    /// Evaluates an expression `ast` in the current model.
    /// When `model_completion` is true it will assign an interpretation for constants and functions that do not have an interpretation in the model.
    /// This function may fail (return [None]) if the argument contains quantifiers or if it is not well-sorted.
    pub fn eval<T>(&self, ast: &T, model_completion: bool) -> Option<T>
    where
        T: Ast,
    {
        let mut tmp: Z3_ast = ast.get_z3_ast();
        let res = {
            unsafe {
                Z3_model_eval(
                    self.ctx.z3_ctx.0,
                    self.z3_mdl,
                    ast.get_z3_ast(),
                    model_completion,
                    &mut tmp,
                )
            }
        };
        if res {
            Some(unsafe { T::wrap(&self.ctx, tmp) })
        } else {
            None
        }
    }

    fn len(&self) -> u32 {
        unsafe {
            Z3_model_get_num_consts(self.ctx.z3_ctx.0, self.z3_mdl)
                + Z3_model_get_num_funcs(self.ctx.z3_ctx.0, self.z3_mdl)
        }
    }

    pub fn iter<'a>(&'a self) -> ModelIter<'a> {
        self.into_iter()
    }

    /// Returns the number of uninterpreted sorts that the model assigns an interpretation to.
    pub fn num_sorts(&self) -> u32 {
        unsafe { Z3_model_get_num_sorts(self.ctx.z3_ctx.0, self.z3_mdl) }
    }

    /// Returns the i-th uninterpreted sort that the model assigns an interpretation to,
    /// or `None` if `i >= self.num_sorts()`.
    pub fn get_sort(&self, i: u32) -> Option<Sort> {
        let z3_sort = unsafe { Z3_model_get_sort(self.ctx.z3_ctx.0, self.z3_mdl, i) }?;
        Some(unsafe { Sort::wrap(&self.ctx, z3_sort) })
    }

    /// Returns the universe of the given sort (the finite set of values Z3 assigned to it),
    /// or `None` if the sort has no interpretation in the model.
    pub fn get_sort_universe(&self, sort: &Sort) -> Option<AstVector> {
        let z3_av =
            unsafe { Z3_model_get_sort_universe(self.ctx.z3_ctx.0, self.z3_mdl, sort.z3_sort) }?;
        Some(unsafe { AstVector::wrap(&self.ctx, z3_av) })
    }

    /// Returns an iterator over the uninterpreted sorts the model assigns an interpretation to.
    pub fn sorts(&self) -> SortIter<'_> {
        SortIter {
            model: self,
            idx: 0,
            len: self.num_sorts(),
        }
    }

    /// Returns an iterator over each uninterpreted sort and its universe in the model.
    pub fn sort_universes(&self) -> impl Iterator<Item = (Sort, AstVector)> + '_ {
        self.sorts().filter_map(|s| {
            let u = self.get_sort_universe(&s)?;
            Some((s, u))
        })
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let p = unsafe { Z3_model_to_string(self.ctx.z3_ctx.0, self.z3_mdl) };
        if p.is_null() {
            return Result::Err(fmt::Error);
        }
        match unsafe { CStr::from_ptr(p) }.to_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Result::Err(fmt::Error),
        }
    }
}

impl fmt::Debug for Model {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl Drop for Model {
    fn drop(&mut self) {
        unsafe { Z3_model_dec_ref(self.ctx.z3_ctx.0, self.z3_mdl) };
    }
}

#[derive(Debug)]
/// <https://z3prover.github.io/api/html/classz3py_1_1_model_ref.html#a7890b7c9bc70cf2a26a343c22d2c8367>
pub struct ModelIter<'a> {
    model: &'a Model,
    idx: u32,
    len: u32,
}

impl<'a> IntoIterator for &'a Model {
    type Item = FuncDecl;
    type IntoIter = ModelIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ModelIter {
            model: self,
            idx: 0,
            len: self.len(),
        }
    }
}

impl Iterator for ModelIter<'_> {
    type Item = FuncDecl;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.len {
            None
        } else {
            let num_consts =
                unsafe { Z3_model_get_num_consts(self.model.ctx.z3_ctx.0, self.model.z3_mdl) };
            if self.idx < num_consts {
                let const_decl = unsafe {
                    Z3_model_get_const_decl(self.model.ctx.z3_ctx.0, self.model.z3_mdl, self.idx)
                        .unwrap()
                };
                self.idx += 1;
                Some(unsafe { FuncDecl::wrap(&self.model.ctx, const_decl) })
            } else {
                let func_decl = unsafe {
                    Z3_model_get_func_decl(
                        self.model.ctx.z3_ctx.0,
                        self.model.z3_mdl,
                        self.idx - num_consts,
                    )
                    .unwrap()
                };
                self.idx += 1;
                Some(unsafe { FuncDecl::wrap(&self.model.ctx, func_decl) })
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = (self.len - self.idx) as usize;
        (len, Some(len))
    }
}

#[derive(Debug)]
pub struct SortIter<'a> {
    model: &'a Model,
    idx: u32,
    len: u32,
}

impl Iterator for SortIter<'_> {
    type Item = Sort;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.len {
            return None;
        }
        let sort = self.model.get_sort(self.idx)?;
        self.idx += 1;
        Some(sort)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = (self.len - self.idx) as usize;
        (len, Some(len))
    }
}

impl FusedIterator for SortIter<'_> {}
impl ExactSizeIterator for SortIter<'_> {}

unsafe impl Translate for Model {
    fn translate(&self, dest: &Context) -> Model {
        unsafe {
            Model::wrap(
                dest,
                Z3_model_translate(self.ctx.z3_ctx.0, self.z3_mdl, dest.z3_ctx.0).unwrap(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Solver;
    use crate::ast::Bool;

    #[test]
    fn test_unsat() {
        use crate::SatResult;
        let solver = Solver::new();
        solver.assert(Bool::from_bool(false));
        assert_eq!(solver.check(), SatResult::Unsat);
        assert!(solver.get_model().is_none());
    }

    #[test]
    fn test_sort_universes() {
        use crate::SatResult;
        use crate::{Sort, Symbol, ast::Dynamic};

        let s = Sort::uninterpreted(Symbol::String("S".to_string()));
        let x = Dynamic::new_const("x", &s);
        let y = Dynamic::new_const("y", &s);

        let solver = Solver::new();
        solver.assert(x.eq(&y).not());
        assert_eq!(solver.check(), SatResult::Sat);

        let model = solver.get_model().unwrap();

        // Individual access
        assert_eq!(model.num_sorts(), 1);
        let sort = model.get_sort(0).unwrap();
        assert!(model.get_sort(1).is_none());

        let universe = model.get_sort_universe(&sort).unwrap();
        assert!(universe.len() >= 2);

        // Iterator access
        let sorts: Vec<_> = model.sorts().collect();
        assert_eq!(sorts.len(), 1);

        // Convenience iterator
        let pairs: Vec<_> = model.sort_universes().collect();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].1.len(), universe.len());
    }
}
