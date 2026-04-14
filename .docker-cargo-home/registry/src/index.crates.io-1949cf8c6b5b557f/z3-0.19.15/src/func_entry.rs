use std::fmt;
use z3_sys::*;

use crate::{
    Context, FuncEntry,
    ast::{Ast, Dynamic},
};

impl FuncEntry {
    pub(crate) unsafe fn wrap(ctx: &Context, z3_func_entry: Z3_func_entry) -> Self {
        unsafe {
            Z3_func_entry_inc_ref(ctx.z3_ctx.0, z3_func_entry);
        }
        Self {
            ctx: ctx.clone(),
            z3_func_entry,
        }
    }

    /// Returns the value of the function.
    pub fn get_value(&self) -> Dynamic {
        unsafe {
            Dynamic::wrap(
                &self.ctx,
                Z3_func_entry_get_value(self.ctx.z3_ctx.0, self.z3_func_entry).unwrap(),
            )
        }
    }

    /// Returns the number of arguments in the function entry.
    pub fn get_num_args(&self) -> u32 {
        unsafe { Z3_func_entry_get_num_args(self.ctx.z3_ctx.0, self.z3_func_entry) }
    }

    /// Returns the arguments of the function entry.
    pub fn get_args(&self) -> Vec<Dynamic> {
        (0..self.get_num_args())
            .map(|i| unsafe {
                Dynamic::wrap(
                    &self.ctx,
                    Z3_func_entry_get_arg(self.ctx.z3_ctx.0, self.z3_func_entry, i).unwrap(),
                )
            })
            .collect()
    }
}

impl fmt::Display for FuncEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "[")?;
        self.get_args()
            .into_iter()
            .try_for_each(|a| write!(f, "{a}, "))?;
        write!(f, "{}", self.get_value())?;
        write!(f, "]")
    }
}

impl fmt::Debug for FuncEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl Drop for FuncEntry {
    fn drop(&mut self) {
        unsafe {
            Z3_func_entry_dec_ref(self.ctx.z3_ctx.0, self.z3_func_entry);
        }
    }
}
