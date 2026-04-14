use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
use std::os::windows::raw::HANDLE;
use windows_sys::Win32::Foundation::MAX_PATH;
use windows_sys::Win32::Storage::FileSystem::{
    FileNameInfo, GetFileInformationByHandleEx, GetFileType, FILE_TYPE_PIPE,
};

pub(super) fn msys_tty_on(handle: BorrowedHandle<'_>) -> bool {
    // SAFETY: We pass a valid handle.
    unsafe { msys_tty_on_unsafe(handle.as_raw_handle()) }
}

// Adopted from Rust's standard library with minimal changes to use windows_sys.
// Source: https://github.com/rust-lang/rust/blob/32ec40c68533f325a3c8fe787b77ef5c9e209b23/library/std/src/sys/pal/windows/io.rs#L82
pub(super) unsafe fn msys_tty_on_unsafe(handle: HANDLE) -> bool {
    // Early return if the handle is not a pipe.
    if GetFileType(handle) != FILE_TYPE_PIPE {
        return false;
    }

    /// Mirrors [`FILE_NAME_INFO`], giving it a fixed length that we can stack
    /// allocate
    ///
    /// [`FILE_NAME_INFO`]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_name_info
    #[repr(C)]
    #[allow(non_snake_case)]
    struct FILE_NAME_INFO {
        FileNameLength: u32,
        FileName: [u16; MAX_PATH as usize],
    }
    let mut name_info = FILE_NAME_INFO {
        FileNameLength: 0,
        FileName: [0; MAX_PATH as usize],
    };
    // Safety: buffer length is fixed.
    let res = GetFileInformationByHandleEx(
        handle,
        FileNameInfo,
        &mut name_info as *mut _ as *mut c_void,
        size_of::<FILE_NAME_INFO>() as u32,
    );
    if res == 0 {
        return false;
    }

    // Use `get` because `FileNameLength` can be out of range.
    let s = match name_info
        .FileName
        .get(..name_info.FileNameLength as usize / 2)
    {
        None => return false,
        Some(s) => s,
    };
    let name = String::from_utf16_lossy(s);
    // Get the file name only.
    let name = name.rsplit('\\').next().unwrap_or(&name);
    // This checks whether 'pty' exists in the file name, which indicates that
    // a pseudo-terminal is attached. To mitigate against false positives
    // (e.g., an actual file name that contains 'pty'), we also require that
    // the file name begins with either the strings 'msys-' or 'cygwin-'.)
    let is_msys = name.starts_with("msys-") || name.starts_with("cygwin-");
    let is_pty = name.contains("-pty");
    is_msys && is_pty
}
