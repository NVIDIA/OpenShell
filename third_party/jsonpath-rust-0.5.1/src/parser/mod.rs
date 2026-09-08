//! The parser for the jsonpath.
//! The module grammar denotes the structure of the parsing grammar

pub mod errors;
mod macros;
pub mod model;
#[allow(clippy::module_inception)]
#[allow(clippy::result_large_err)]
pub mod parser;
