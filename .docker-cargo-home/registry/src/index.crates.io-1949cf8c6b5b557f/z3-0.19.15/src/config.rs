use log::debug;
use std::ffi::CString;

use z3_sys::*;

use crate::Config;

impl Config {
    /// Create a configuration object for the Z3 context object.
    ///
    /// Configurations are created in order to assign parameters
    /// prior to creating contexts for Z3 interaction. For example,
    /// if the users wishes to use proof generation, then call:
    ///
    /// ```
    /// use z3::Config;
    ///
    /// let mut cfg = Config::new();
    /// cfg.set_proof_generation(true);
    /// ```
    ///
    /// # See also
    ///
    /// - [`with_z3_config`](crate::with_z3_config)
    pub fn new() -> Config {
        Config {
            kvs: Vec::new(),
            z3_cfg: unsafe {
                let p = Z3_mk_config().unwrap();
                debug!("new config {p:p}");
                p
            },
        }
    }

    /// Set a configuration parameter.
    ///
    /// # See also
    ///
    /// - [`Config::set_bool_param_value()`]
    pub fn set_param_value(&mut self, k: &str, v: &str) {
        let ks = CString::new(k).unwrap();
        let vs = CString::new(v).unwrap();
        self.kvs.push((ks, vs));
        unsafe {
            Z3_set_param_value(
                self.z3_cfg,
                self.kvs.last().unwrap().0.as_ptr(),
                self.kvs.last().unwrap().1.as_ptr(),
            );
        };
    }

    /// Set a configuration parameter.
    ///
    /// This is a helper function.
    ///
    /// # See also
    ///
    /// - [`Config::set_param_value()`]
    pub fn set_bool_param_value(&mut self, k: &str, v: bool) {
        self.set_param_value(k, if v { "true" } else { "false" });
    }

    /// Enable or disable proof generation.
    ///
    /// # See also
    ///
    /// - [`Solver::check()`](crate::Solver::check)
    /// - [`Solver::get_proof()`](crate::Solver::get_proof)
    pub fn set_proof_generation(&mut self, b: bool) {
        self.set_bool_param_value("proof", b);
    }

    /// Enable or disable model generation.
    ///
    /// # See also
    ///
    /// - [`Solver::check()`](crate::Solver::check)
    /// - [`Solver::get_model()`](crate::Solver::get_model)
    pub fn set_model_generation(&mut self, b: bool) {
        self.set_bool_param_value("model", b);
    }

    pub fn set_debug_ref_count(&mut self, b: bool) {
        self.set_bool_param_value("debug_ref_count", b);
    }

    pub fn set_timeout_msec(&mut self, ms: u64) {
        self.set_param_value("timeout", &format!("{ms}"));
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        unsafe { Z3_del_config(self.z3_cfg) };
    }
}
