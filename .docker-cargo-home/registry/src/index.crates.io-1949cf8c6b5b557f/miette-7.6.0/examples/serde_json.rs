//! This example shows how to integrate miette with serde_json
//! so the decoding source will be annotated with the decoding error,
//! providing contextual information about the error.

use miette::{IntoDiagnostic, SourceOffset};
use serde_json::{self, json};

#[derive(Debug, serde::Deserialize)]
struct Library {
    #[allow(unused)]
    name: String,
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("malformed json provided")]
struct SerdeError {
    cause: serde_json::Error,
    #[source_code]
    input: String,
    #[label("{cause}")]
    location: SourceOffset,
}

impl SerdeError {
    /// Takes the input and the `serde_json::Error` and returns a SerdeError
    /// that can be rendered nicely with miette.
    pub fn from_serde_error(input: impl Into<String>, cause: serde_json::Error) -> Self {
        let input = input.into();
        let location = SourceOffset::from_location(&input, cause.line(), cause.column());
        Self {
            cause,
            input,
            location,
        }
    }
}

fn main() -> miette::Result<()> {
    let input = serde_json::to_string_pretty(&json!({
        "name": 123
    }))
    .into_diagnostic()?;

    let _library: Library =
        serde_json::from_str(&input).map_err(|cause| SerdeError::from_serde_error(input, cause))?;

    Ok(())
}
