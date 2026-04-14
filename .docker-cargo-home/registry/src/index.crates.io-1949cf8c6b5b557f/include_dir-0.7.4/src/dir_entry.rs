use crate::{Dir, File};
use std::path::Path;

/// A directory entry, roughly analogous to [`std::fs::DirEntry`].
#[derive(Debug, Clone, PartialEq)]
pub enum DirEntry<'a> {
    /// A directory.
    Dir(Dir<'a>),
    /// A file.
    File(File<'a>),
}

impl<'a> DirEntry<'a> {
    /// The [`DirEntry`]'s full path.
    pub fn path(&self) -> &'a Path {
        match self {
            DirEntry::Dir(d) => d.path(),
            DirEntry::File(f) => f.path(),
        }
    }

    /// Try to get this as a [`Dir`], if it is one.
    pub fn as_dir(&self) -> Option<&Dir<'a>> {
        match self {
            DirEntry::Dir(d) => Some(d),
            DirEntry::File(_) => None,
        }
    }

    /// Try to get this as a [`File`], if it is one.
    pub fn as_file(&self) -> Option<&File<'a>> {
        match self {
            DirEntry::File(f) => Some(f),
            DirEntry::Dir(_) => None,
        }
    }

    /// Get this item's sub-items, if it has any.
    pub fn children(&self) -> &'a [DirEntry<'a>] {
        match self {
            DirEntry::Dir(d) => d.entries(),
            DirEntry::File(_) => &[],
        }
    }
}
