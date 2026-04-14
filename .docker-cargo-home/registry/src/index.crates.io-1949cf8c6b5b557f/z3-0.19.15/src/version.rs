use std::ffi::CStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Version {
    major: u32,
    minor: u32,
    build_number: u32,
    revision_number: u32,
}

pub fn version() -> Version {
    let mut ver = Version::default();
    unsafe {
        z3_sys::Z3_get_version(
            &mut ver.major,
            &mut ver.minor,
            &mut ver.build_number,
            &mut ver.revision_number,
        );
    }
    ver
}

pub fn full_version() -> &'static str {
    let ver_ptr = unsafe { z3_sys::Z3_get_full_version() };
    let ver = unsafe { CStr::from_ptr(ver_ptr) };
    ver.to_str()
        .expect("Z3_get_full_version returned non-UTF-8 characters")
}
