//! Error types for the gateway microVM subsystem.

use std::path::PathBuf;

/// Errors that can occur when configuring or starting a microVM.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// libkrun failed to create a configuration context.
    #[error("failed to create libkrun context (error code: {0})")]
    ContextCreation(i32),

    /// The VM configuration call failed.
    #[error("failed to configure VM ({call}): libkrun error code {code}")]
    Configuration {
        /// Which libkrun API call failed.
        call: &'static str,
        /// The negative error code returned by libkrun.
        code: i32,
    },

    /// The rootfs path provided does not exist or is not a directory.
    #[error("rootfs path does not exist or is not a directory: {0}")]
    RootfsNotFound(PathBuf),

    /// `krun_start_enter` returned an error instead of booting the VM.
    #[error("failed to start microVM (libkrun error code: {0})")]
    StartFailed(i32),

    /// `fork()` failed when trying to start the VM in a child process.
    #[error("fork failed: {0}")]
    Fork(std::io::Error),

    /// A string argument contained an interior null byte and could not be
    /// converted to a C string.
    #[error("argument contains interior null byte: {0}")]
    NulError(#[from] std::ffi::NulError),
}
