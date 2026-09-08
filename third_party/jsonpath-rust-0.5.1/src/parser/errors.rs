use pest::iterators::Pairs;
use thiserror::Error;

use super::parser::Rule;

#[derive(Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum JsonPathParserError<'a> {
    #[error("Failed to parse rule: {0}")]
    PestError(#[from] pest::error::Error<Rule>),
    #[error("Failed to parse JSON: {0}")]
    JsonParsingError(#[from] serde_json::Error),
    #[error("{0}")]
    ParserError(String),
    #[error("Unexpected rule {0:?} when trying to parse logic atom: {1:?}")]
    UnexpectedRuleLogicError(Rule, Pairs<'a, Rule>),
    #[error("Unexpected `none` when trying to parse logic atom: {0:?}")]
    UnexpectedNoneLogicError(Pairs<'a, Rule>),
}

pub fn parser_err(cause: &str) -> JsonPathParserError<'_> {
    JsonPathParserError::ParserError(format!("Failed to parse JSONPath: {cause}"))
}
