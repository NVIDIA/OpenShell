use std::{
    error::Error,
    fmt::{Debug, Display},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{Diagnostic, LabeledSpan, Severity};

/// Diagnostic that can be created at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MietteDiagnostic {
    /// Displayed diagnostic message
    pub message: String,
    /// Unique diagnostic code to look up more information
    /// about this Diagnostic. Ideally also globally unique, and documented
    /// in the toplevel crate's documentation for easy searching.
    /// Rust path format (`foo::bar::baz`) is recommended, but more classic
    /// codes like `E0123` will work just fine
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub code: Option<String>,
    /// [`Diagnostic`] severity. Intended to be used by
    /// [`ReportHandler`](crate::ReportHandler)s to change the way different
    /// [`Diagnostic`]s are displayed. Defaults to [`Severity::Error`]
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub severity: Option<Severity>,
    /// Additional help text related to this Diagnostic
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub help: Option<String>,
    /// URL to visit for a more detailed explanation/help about this
    /// [`Diagnostic`].
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub url: Option<String>,
    /// Labels to apply to this `Diagnostic`'s [`Diagnostic::source_code`]
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub labels: Option<Vec<LabeledSpan>>,
}

impl Display for MietteDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.message)
    }
}

impl Error for MietteDiagnostic {}

impl Diagnostic for MietteDiagnostic {
    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.code
            .as_ref()
            .map(Box::new)
            .map(|c| c as Box<dyn Display>)
    }

    fn severity(&self) -> Option<Severity> {
        self.severity
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.help
            .as_ref()
            .map(Box::new)
            .map(|c| c as Box<dyn Display>)
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.url
            .as_ref()
            .map(Box::new)
            .map(|c| c as Box<dyn Display>)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        self.labels
            .as_ref()
            .map(|ls| ls.iter().cloned())
            .map(Box::new)
            .map(|b| b as Box<dyn Iterator<Item = LabeledSpan>>)
    }
}

impl MietteDiagnostic {
    /// Create a new dynamic diagnostic with the given message.
    ///
    /// # Examples
    /// ```
    /// use miette::{Diagnostic, MietteDiagnostic, Severity};
    ///
    /// let diag = MietteDiagnostic::new("Oops, something went wrong!");
    /// assert_eq!(diag.to_string(), "Oops, something went wrong!");
    /// assert_eq!(diag.message, "Oops, something went wrong!");
    /// ```
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            labels: None,
            severity: None,
            code: None,
            help: None,
            url: None,
        }
    }

    /// Return new diagnostic with the given code.
    ///
    /// # Examples
    /// ```
    /// use miette::{Diagnostic, MietteDiagnostic};
    ///
    /// let diag = MietteDiagnostic::new("Oops, something went wrong!").with_code("foo::bar::baz");
    /// assert_eq!(diag.message, "Oops, something went wrong!");
    /// assert_eq!(diag.code, Some("foo::bar::baz".to_string()));
    /// ```
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    /// Return new diagnostic with the given severity.
    ///
    /// # Examples
    /// ```
    /// use miette::{Diagnostic, MietteDiagnostic, Severity};
    ///
    /// let diag = MietteDiagnostic::new("I warn you to stop!").with_severity(Severity::Warning);
    /// assert_eq!(diag.message, "I warn you to stop!");
    /// assert_eq!(diag.severity, Some(Severity::Warning));
    /// ```
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Return new diagnostic with the given help message.
    ///
    /// # Examples
    /// ```
    /// use miette::{Diagnostic, MietteDiagnostic};
    ///
    /// let diag = MietteDiagnostic::new("PC is not working").with_help("Try to reboot it again");
    /// assert_eq!(diag.message, "PC is not working");
    /// assert_eq!(diag.help, Some("Try to reboot it again".to_string()));
    /// ```
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Return new diagnostic with the given URL.
    ///
    /// # Examples
    /// ```
    /// use miette::{Diagnostic, MietteDiagnostic};
    ///
    /// let diag = MietteDiagnostic::new("PC is not working")
    ///     .with_url("https://letmegooglethat.com/?q=Why+my+pc+doesn%27t+work");
    /// assert_eq!(diag.message, "PC is not working");
    /// assert_eq!(
    ///     diag.url,
    ///     Some("https://letmegooglethat.com/?q=Why+my+pc+doesn%27t+work".to_string())
    /// );
    /// ```
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Return new diagnostic with the given label.
    ///
    /// Discards previous labels
    ///
    /// # Examples
    /// ```
    /// use miette::{Diagnostic, LabeledSpan, MietteDiagnostic};
    ///
    /// let source = "cpp is the best language";
    ///
    /// let label = LabeledSpan::at(0..3, "This should be Rust");
    /// let diag = MietteDiagnostic::new("Wrong best language").with_label(label.clone());
    /// assert_eq!(diag.message, "Wrong best language");
    /// assert_eq!(diag.labels, Some(vec![label]));
    /// ```
    pub fn with_label(mut self, label: impl Into<LabeledSpan>) -> Self {
        self.labels = Some(vec![label.into()]);
        self
    }

    /// Return new diagnostic with the given labels.
    ///
    /// Discards previous labels
    ///
    /// # Examples
    /// ```
    /// use miette::{Diagnostic, LabeledSpan, MietteDiagnostic};
    ///
    /// let source = "helo wrld";
    ///
    /// let labels = vec![
    ///     LabeledSpan::at_offset(3, "add 'l'"),
    ///     LabeledSpan::at_offset(6, "add 'r'"),
    /// ];
    /// let diag = MietteDiagnostic::new("Typos in 'hello world'").with_labels(labels.clone());
    /// assert_eq!(diag.message, "Typos in 'hello world'");
    /// assert_eq!(diag.labels, Some(labels));
    /// ```
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = LabeledSpan>) -> Self {
        self.labels = Some(labels.into_iter().collect());
        self
    }

    /// Return new diagnostic with new label added to the existing ones.
    ///
    /// # Examples
    /// ```
    /// use miette::{Diagnostic, LabeledSpan, MietteDiagnostic};
    ///
    /// let source = "helo wrld";
    ///
    /// let label1 = LabeledSpan::at_offset(3, "add 'l'");
    /// let label2 = LabeledSpan::at_offset(6, "add 'r'");
    /// let diag = MietteDiagnostic::new("Typos in 'hello world'")
    ///     .and_label(label1.clone())
    ///     .and_label(label2.clone());
    /// assert_eq!(diag.message, "Typos in 'hello world'");
    /// assert_eq!(diag.labels, Some(vec![label1, label2]));
    /// ```
    pub fn and_label(mut self, label: impl Into<LabeledSpan>) -> Self {
        let mut labels = self.labels.unwrap_or_default();
        labels.push(label.into());
        self.labels = Some(labels);
        self
    }

    /// Return new diagnostic with new labels added to the existing ones.
    ///
    /// # Examples
    /// ```
    /// use miette::{Diagnostic, LabeledSpan, MietteDiagnostic};
    ///
    /// let source = "helo wrld";
    ///
    /// let label1 = LabeledSpan::at_offset(3, "add 'l'");
    /// let label2 = LabeledSpan::at_offset(6, "add 'r'");
    /// let label3 = LabeledSpan::at_offset(9, "add '!'");
    /// let diag = MietteDiagnostic::new("Typos in 'hello world!'")
    ///     .and_label(label1.clone())
    ///     .and_labels([label2.clone(), label3.clone()]);
    /// assert_eq!(diag.message, "Typos in 'hello world!'");
    /// assert_eq!(diag.labels, Some(vec![label1, label2, label3]));
    /// ```
    pub fn and_labels(mut self, labels: impl IntoIterator<Item = LabeledSpan>) -> Self {
        let mut all_labels = self.labels.unwrap_or_default();
        all_labels.extend(labels);
        self.labels = Some(all_labels);
        self
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_serialize_miette_diagnostic() {
    use serde_json::json;

    use crate::diagnostic;

    let diag = diagnostic!("message");
    let json = json!({ "message": "message" });
    assert_eq!(json!(diag), json);

    let diag = diagnostic!(
        code = "code",
        help = "help",
        url = "url",
        labels = [
            LabeledSpan::at_offset(0, "label1"),
            LabeledSpan::at(1..3, "label2")
        ],
        severity = Severity::Warning,
        "message"
    );
    let json = json!({
        "message": "message",
        "code": "code",
        "help": "help",
        "url": "url",
        "severity": "Warning",
        "labels": [
            {
                "span": {
                    "offset": 0,
                    "length": 0
                },
                "label": "label1",
                "primary": false
            },
            {
                "span": {
                    "offset": 1,
                    "length": 2
                },
                "label": "label2",
                "primary": false
            }
        ]
    });
    assert_eq!(json!(diag), json);
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_miette_diagnostic() {
    use serde_json::json;

    use crate::diagnostic;

    let json = json!({ "message": "message" });
    let diag = diagnostic!("message");
    assert_eq!(diag, serde_json::from_value(json).unwrap());

    let json = json!({
        "message": "message",
        "help": null,
        "code": null,
        "severity": null,
        "url": null,
        "labels": null
    });
    assert_eq!(diag, serde_json::from_value(json).unwrap());

    let diag = diagnostic!(
        code = "code",
        help = "help",
        url = "url",
        labels = [
            LabeledSpan::at_offset(0, "label1"),
            LabeledSpan::at(1..3, "label2")
        ],
        severity = Severity::Warning,
        "message"
    );
    let json = json!({
        "message": "message",
        "code": "code",
        "help": "help",
        "url": "url",
        "severity": "Warning",
        "labels": [
            {
                "span": {
                    "offset": 0,
                    "length": 0
                },
                "label": "label1",
                "primary": false
            },
            {
                "span": {
                    "offset": 1,
                    "length": 2
                },
                "label": "label2",
                "primary": false
            }
        ]
    });
    assert_eq!(diag, serde_json::from_value(json).unwrap());
}
