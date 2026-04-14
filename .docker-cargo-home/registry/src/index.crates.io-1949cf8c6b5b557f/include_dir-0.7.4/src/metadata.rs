use std::time::{Duration, SystemTime};

/// Basic metadata for a file.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Metadata {
    accessed: Duration,
    created: Duration,
    modified: Duration,
}

impl Metadata {
    /// Create a new [`Metadata`] using the number of seconds since the
    /// [`SystemTime::UNIX_EPOCH`].
    pub const fn new(accessed: Duration, created: Duration, modified: Duration) -> Self {
        Metadata {
            accessed,
            created,
            modified,
        }
    }

    /// Get the time this file was last accessed.
    ///
    /// See also: [`std::fs::Metadata::accessed()`].
    pub fn accessed(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + self.accessed
    }

    /// Get the time this file was created.
    ///
    /// See also: [`std::fs::Metadata::created()`].
    pub fn created(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + self.created
    }

    /// Get the time this file was last modified.
    ///
    /// See also: [`std::fs::Metadata::modified()`].
    pub fn modified(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + self.modified
    }
}
