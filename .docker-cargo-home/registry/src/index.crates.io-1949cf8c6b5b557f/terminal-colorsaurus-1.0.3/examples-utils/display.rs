use std::fmt;

pub(crate) struct DisplayAsDebug<T>(pub(crate) T);

impl<T> From<T> for DisplayAsDebug<T> {
    fn from(value: T) -> Self {
        DisplayAsDebug(value)
    }
}

impl<T: fmt::Display> fmt::Debug for DisplayAsDebug<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
