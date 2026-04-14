use crate::{Dir, DirEntry};
use glob::{Pattern, PatternError};

impl<'a> Dir<'a> {
    /// Search for a file or directory with a glob pattern.
    pub fn find(&self, glob: &str) -> Result<impl Iterator<Item = &'a DirEntry<'a>>, PatternError> {
        let pattern = Pattern::new(glob)?;

        Ok(Globs::new(pattern, self))
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Globs<'a> {
    stack: Vec<&'a DirEntry<'a>>,
    pattern: Pattern,
}

impl<'a> Globs<'a> {
    pub(crate) fn new(pattern: Pattern, root: &Dir<'a>) -> Globs<'a> {
        let stack = root.entries().iter().collect();
        Globs { stack, pattern }
    }
}

impl<'a> Iterator for Globs<'a> {
    type Item = &'a DirEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(item) = self.stack.pop() {
            self.stack.extend(item.children());

            if self.pattern.matches_path(item.path()) {
                return Some(item);
            }
        }

        None
    }
}
