use std::ffi::{CStr, CString};
use std::fmt;
use z3_sys::*;

use crate::{Context, Params, Symbol};

impl Params {
    unsafe fn wrap(ctx: &Context, z3_params: Z3_params) -> Params {
        unsafe {
            Z3_params_inc_ref(ctx.z3_ctx.0, z3_params);
        }
        Params {
            ctx: ctx.clone(),
            z3_params,
        }
    }

    pub fn new() -> Params {
        let ctx = &Context::thread_local();
        unsafe { Self::wrap(ctx, Z3_mk_params(ctx.z3_ctx.0).unwrap()) }
    }

    pub fn set_symbol<K: Into<Symbol>, V: Into<Symbol>>(&mut self, k: K, v: V) {
        unsafe {
            Z3_params_set_symbol(
                self.ctx.z3_ctx.0,
                self.z3_params,
                k.into().as_z3_symbol(),
                v.into().as_z3_symbol(),
            );
        };
    }

    pub fn set_bool<K: Into<Symbol>>(&mut self, k: K, v: bool) {
        unsafe {
            Z3_params_set_bool(
                self.ctx.z3_ctx.0,
                self.z3_params,
                k.into().as_z3_symbol(),
                v,
            );
        };
    }

    pub fn set_f64<K: Into<Symbol>>(&mut self, k: K, v: f64) {
        unsafe {
            Z3_params_set_double(
                self.ctx.z3_ctx.0,
                self.z3_params,
                k.into().as_z3_symbol(),
                v,
            );
        };
    }

    pub fn set_u32<K: Into<Symbol>>(&mut self, k: K, v: u32) {
        unsafe {
            Z3_params_set_uint(
                self.ctx.z3_ctx.0,
                self.z3_params,
                k.into().as_z3_symbol(),
                v,
            );
        };
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

/// Get a global (or module) parameter.
///
/// # See also
///
/// - [`set_global_param()`]
/// - [`reset_all_global_params()`]
pub fn get_global_param(k: &str) -> Option<String> {
    let ks = CString::new(k).unwrap();
    let mut ptr = std::ptr::null();
    if unsafe { Z3_global_param_get(ks.as_ptr(), &mut ptr as Z3_string_ptr) } {
        let vs = unsafe { CStr::from_ptr(ptr) };
        vs.to_str().ok().map(|vs| vs.to_owned())
    } else {
        None
    }
}

/// Set a global (or module) parameter. This setting is shared by all Z3 contexts.
///
/// # See also
///
/// - [`get_global_param()`]
/// - [`reset_all_global_params()`]
pub fn set_global_param(k: &str, v: &str) {
    let ks = CString::new(k).unwrap();
    let vs = CString::new(v).unwrap();
    unsafe { Z3_global_param_set(ks.as_ptr(), vs.as_ptr()) };
}

/// Restore the value of all global (and module) parameters. This command will not affect already created objects (such as tactics and solvers).
///
/// # See also
///
/// - [`get_global_param()`]
/// - [`set_global_param()`]
pub fn reset_all_global_params() {
    unsafe { Z3_global_param_reset_all() };
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let p = unsafe { Z3_params_to_string(self.ctx.z3_ctx.0, self.z3_params) };
        if p.is_null() {
            return Result::Err(fmt::Error);
        }
        match unsafe { CStr::from_ptr(p) }.to_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Result::Err(fmt::Error),
        }
    }
}

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl Drop for Params {
    fn drop(&mut self) {
        unsafe { Z3_params_dec_ref(self.ctx.z3_ctx.0, self.z3_params) };
    }
}
