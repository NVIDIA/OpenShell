/*!
Default trait implementations for [`Diagnostic`].
*/

use std::{convert::Infallible, fmt::Display};

use crate::{Diagnostic, LabeledSpan, Severity, SourceCode};

impl Diagnostic for Infallible {
    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        match *self {}
    }

    fn severity(&self) -> Option<Severity> {
        match *self {}
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        match *self {}
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        match *self {}
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        match *self {}
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        match *self {}
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        match *self {}
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Report;

    /// Test that [`Infallible`] implements [`Diagnostic`] by seeing if a function that's generic over `Diagnostic`
    /// will accept `Infallible` as a type parameter.
    #[test]
    fn infallible() {
        let _ = Report::new::<Infallible>;
    }
}
