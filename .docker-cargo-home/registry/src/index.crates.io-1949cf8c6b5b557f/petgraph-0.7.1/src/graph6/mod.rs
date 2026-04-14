//! Traits related to [graph6 format](https://users.cecs.anu.edu.au/~bdm/data/formats.txt) for undirected graphs.

pub use self::graph6_decoder::*;
pub use self::graph6_encoder::*;

mod graph6_decoder;
mod graph6_encoder;
