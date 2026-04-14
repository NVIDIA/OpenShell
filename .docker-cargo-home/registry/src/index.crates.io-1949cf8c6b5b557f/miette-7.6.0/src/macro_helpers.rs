use crate::protocol::{LabeledSpan, SourceSpan};

// Huge thanks to @jam1gamer for this hack:
// https://twitter.com/jam1garner/status/1515887996444323840

#[doc(hidden)]
pub trait IsOption {}
impl<T> IsOption for Option<T> {}

#[doc(hidden)]
#[derive(Debug, Default)]
pub struct OptionalWrapper<T>(pub core::marker::PhantomData<T>);

impl<T> OptionalWrapper<T> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

#[doc(hidden)]
pub trait ToOption {
    #[doc(hidden)]
    fn to_option<T>(self, value: T) -> Option<T>;
}

impl<T> OptionalWrapper<T>
where
    T: IsOption,
{
    #[doc(hidden)]
    pub fn to_option(self, value: &T) -> &T {
        value
    }
}

impl<T> ToOption for &OptionalWrapper<T> {
    fn to_option<U>(self, value: U) -> Option<U> {
        Some(value)
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct ToLabelSpanWrapper {}
pub trait ToLabeledSpan<T> {
    #[doc(hidden)]
    fn to_labeled_span(span: T) -> LabeledSpan;
}
impl ToLabeledSpan<LabeledSpan> for ToLabelSpanWrapper {
    fn to_labeled_span(span: LabeledSpan) -> LabeledSpan {
        span
    }
}
impl<T> ToLabeledSpan<T> for ToLabelSpanWrapper
where
    T: Into<SourceSpan>,
{
    fn to_labeled_span(span: T) -> LabeledSpan {
        LabeledSpan::new_with_span(None, span.into())
    }
}
