use core::fmt::{self, Debug, Display};

use std::error::Error as StdError;

use crate::{Diagnostic, LabeledSpan, Report, SourceCode};

use crate as miette;

#[repr(transparent)]
pub(crate) struct DisplayError<M>(pub(crate) M);

impl<M> Debug for DisplayError<M>
where
    M: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<M> Display for DisplayError<M>
where
    M: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<M> StdError for DisplayError<M> where M: Display + 'static {}
impl<M> Diagnostic for DisplayError<M> where M: Display + 'static {}

#[repr(transparent)]
pub(crate) struct MessageError<M>(pub(crate) M);

impl<M> Debug for MessageError<M>
where
    M: Display + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<M> Display for MessageError<M>
where
    M: Display + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<M> StdError for MessageError<M> where M: Display + Debug + 'static {}
impl<M> Diagnostic for MessageError<M> where M: Display + Debug + 'static {}

#[repr(transparent)]
pub(crate) struct BoxedError(pub(crate) Box<dyn Diagnostic + Send + Sync>);

impl Diagnostic for BoxedError {
    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.0.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.0.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.0.help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.0.url()
    }

    fn labels<'a>(&'a self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + 'a>> {
        self.0.labels()
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.0.source_code()
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.0.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.0.diagnostic_source()
    }
}

impl Debug for BoxedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Display for BoxedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl StdError for BoxedError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.0.source()
    }

    fn description(&self) -> &str {
        #[allow(deprecated)]
        self.0.description()
    }

    fn cause(&self) -> Option<&dyn StdError> {
        #[allow(deprecated)]
        self.0.cause()
    }
}

pub(crate) struct WithSourceCode<E, C> {
    pub(crate) error: E,
    pub(crate) source_code: C,
}

impl<E: Diagnostic, C: SourceCode> Diagnostic for WithSourceCode<E, C> {
    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.error.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.error.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.error.help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.error.url()
    }

    fn labels<'a>(&'a self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + 'a>> {
        self.error.labels()
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.error.source_code().or(Some(&self.source_code))
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.error.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.error.diagnostic_source()
    }
}

impl<C: SourceCode> Diagnostic for WithSourceCode<Report, C> {
    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.error.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.error.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.error.help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.error.url()
    }

    fn labels<'a>(&'a self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + 'a>> {
        self.error.labels()
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.error.source_code().or(Some(&self.source_code))
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.error.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.error.diagnostic_source()
    }
}

impl<E: Debug, C> Debug for WithSourceCode<E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.error, f)
    }
}

impl<E: Display, C> Display for WithSourceCode<E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.error, f)
    }
}

impl<E: StdError, C> StdError for WithSourceCode<E, C> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.error.source()
    }
}

impl<C> StdError for WithSourceCode<Report, C> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.error.source()
    }
}

#[cfg(test)]
mod tests {
    use thiserror::Error;

    use crate::{Diagnostic, LabeledSpan, Report, SourceCode, SourceSpan};

    #[derive(Error, Debug)]
    #[error("inner")]
    struct Inner {
        pub(crate) at: SourceSpan,
        pub(crate) source_code: Option<String>,
    }

    impl Diagnostic for Inner {
        fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
            Some(Box::new(std::iter::once(LabeledSpan::underline(self.at))))
        }

        fn source_code(&self) -> Option<&dyn SourceCode> {
            self.source_code.as_ref().map(|s| s as _)
        }
    }

    #[test]
    fn no_override() {
        let inner_source = "hello world";
        let outer_source = "abc";

        let report = Report::from(Inner {
            at: (0..5).into(),
            source_code: Some(inner_source.to_string()),
        })
        .with_source_code(outer_source.to_string());

        let underlined = String::from_utf8(
            report
                .source_code()
                .unwrap()
                .read_span(&(0..5).into(), 0, 0)
                .unwrap()
                .data()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(underlined, "hello");
    }

    #[test]
    #[cfg(feature = "fancy")]
    fn two_source_codes() {
        #[derive(Error, Debug)]
        #[error("outer")]
        struct Outer {
            pub(crate) errors: Vec<Inner>,
        }

        impl Diagnostic for Outer {
            fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
                Some(Box::new(self.errors.iter().map(|e| e as _)))
            }
        }

        let inner_source = "hello world";
        let outer_source = "abc";

        let report = Report::from(Outer {
            errors: vec![
                Inner {
                    at: (0..5).into(),
                    source_code: Some(inner_source.to_string()),
                },
                Inner {
                    at: (1..2).into(),
                    source_code: None,
                },
            ],
        })
        .with_source_code(outer_source.to_string());

        let message = format!("{:?}", report);
        assert!(message.contains(inner_source));
        assert!(message.contains(outer_source));
    }
}
