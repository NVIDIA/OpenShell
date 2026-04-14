use std::ffi::CStr;
use std::fmt;

use z3_sys::*;

use crate::{Context, Statistics};

/// The value for a key in [`Statistics`].
///
/// # See also:
///
/// - [`StatisticsEntry`]
/// - [`Statistics::value`]
#[derive(Clone, Debug)]
pub enum StatisticsValue {
    UInt(u32),
    Double(f64),
}

/// A key, value entry within [`Statistics`].
///
/// # See also:
///
/// - [`Statistics::entries`]
#[derive(Clone, Debug)]
pub struct StatisticsEntry {
    pub key: String,
    pub value: StatisticsValue,
}

impl Statistics {
    /// Wrap a raw [`Z3_stats`], managing refcounts.
    pub(crate) unsafe fn wrap(ctx: &Context, z3_stats: Z3_stats) -> Statistics {
        unsafe {
            Z3_stats_inc_ref(ctx.z3_ctx.0, z3_stats);
        }
        Statistics {
            ctx: ctx.clone(),
            z3_stats,
        }
    }

    /// Get the statistics value at the given index.
    ///
    /// # Safety:
    ///
    /// This assumes that `idx` is a valid index.
    unsafe fn value_at_idx(&self, idx: u32) -> StatisticsValue {
        unsafe {
            if Z3_stats_is_uint(self.ctx.z3_ctx.0, self.z3_stats, idx) {
                StatisticsValue::UInt(Z3_stats_get_uint_value(
                    self.ctx.z3_ctx.0,
                    self.z3_stats,
                    idx,
                ))
            } else {
                StatisticsValue::Double(Z3_stats_get_double_value(
                    self.ctx.z3_ctx.0,
                    self.z3_stats,
                    idx,
                ))
            }
        }
    }

    /// Get the statistics value for the given `key`.
    pub fn value(&self, key: &str) -> Option<StatisticsValue> {
        unsafe {
            let size = Z3_stats_size(self.ctx.z3_ctx.0, self.z3_stats);
            for idx in 0..size {
                let k = CStr::from_ptr(Z3_stats_get_key(self.ctx.z3_ctx.0, self.z3_stats, idx));
                if k.to_str().unwrap() == key {
                    return Some(self.value_at_idx(idx));
                }
            }
            None
        }
    }

    /// Iterate over all of the entries in this set of statistics.
    pub fn entries(&self) -> impl Iterator<Item = StatisticsEntry> + '_ {
        let p = unsafe { Z3_stats_size(self.ctx.z3_ctx.0, self.z3_stats) };
        (0..p).map(move |n| unsafe {
            let t = Z3_stats_get_key(self.ctx.z3_ctx.0, self.z3_stats, n);
            StatisticsEntry {
                key: CStr::from_ptr(t).to_str().unwrap().to_owned(),
                value: self.value_at_idx(n),
            }
        })
    }
}

impl Clone for Statistics {
    fn clone(&self) -> Self {
        unsafe { Self::wrap(&self.ctx, self.z3_stats) }
    }
}

impl fmt::Display for Statistics {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "<z3.stats>")
    }
}

impl fmt::Debug for Statistics {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let mut s = f.debug_struct("Statistics");
        for e in self.entries() {
            match e.value {
                StatisticsValue::UInt(v) => s.field(&e.key, &v),
                StatisticsValue::Double(v) => s.field(&e.key, &v),
            };
        }
        s.finish()
    }
}

impl Drop for Statistics {
    fn drop(&mut self) {
        unsafe {
            Z3_stats_dec_ref(self.ctx.z3_ctx.0, self.z3_stats);
        }
    }
}
