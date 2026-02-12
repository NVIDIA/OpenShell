//! Generated protocol buffer code.
//!
//! This module re-exports the generated protobuf types and service definitions.

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod navigator {
    include!(concat!(env!("OUT_DIR"), "/navigator.v1.rs"));
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod datamodel {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/navigator.datamodel.v1.rs"));
    }
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod sandbox {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/navigator.sandbox.v1.rs"));
    }
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod test {
    include!(concat!(env!("OUT_DIR"), "/navigator.test.v1.rs"));
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod inference {
    pub mod v1 {
        include!("navigator.inference.v1.rs");
    }
}

pub use datamodel::v1::*;
pub use inference::v1::*;
pub use navigator::*;
pub use sandbox::v1::*;
pub use test::ObjectForTest;
