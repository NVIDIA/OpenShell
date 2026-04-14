use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "macos")] {
        mod macos;
        pub(crate) use macos::*;
    } else if #[cfg(unix)] {
        mod unix;
        pub(crate) use unix::*;
    } else if #[cfg(windows)] {
        mod windows;
        pub(crate) use windows::*;
    }
}
