/// Return early with an error.
///
/// This macro is equivalent to `return Err(From::from($err))`.
///
/// # Example
///
/// ```
/// # use miette::{bail, Result};
/// #
/// # fn has_permission(user: usize, resource: usize) -> bool {
/// #     true
/// # }
/// #
/// # fn main() -> Result<()> {
/// #     let user = 0;
/// #     let resource = 0;
/// #
/// if !has_permission(user, resource) {
#[cfg_attr(
    not(feature = "no-format-args-capture"),
    doc = r#"     bail!("permission denied for accessing {resource}");"#
)]
#[cfg_attr(
    feature = "no-format-args-capture",
    doc = r#"     bail!("permission denied for accessing {}", resource);"#
)]
/// }
/// #     Ok(())
/// # }
/// ```
///
/// ```
/// # use miette::{bail, Result};
/// # use thiserror::Error;
/// #
/// # const MAX_DEPTH: usize = 1;
/// #
/// #[derive(Error, Debug)]
/// enum ScienceError {
///     #[error("recursion limit exceeded")]
///     RecursionLimitExceeded,
///     # #[error("...")]
///     # More = (stringify! {
///     ...
///     # }, 1).1,
/// }
///
/// # fn main() -> Result<()> {
/// #     let depth = 0;
/// #     let err: &'static dyn std::error::Error = &ScienceError::RecursionLimitExceeded;
/// #
/// if depth > MAX_DEPTH {
///     bail!(ScienceError::RecursionLimitExceeded);
/// }
/// #     Ok(())
/// # }
/// ```
///
/// ```
/// use miette::{bail, Result, Severity};
///
/// fn divide(x: f64, y: f64) -> Result<f64> {
///     if y.abs() < 1e-3 {
///         bail!(
///             severity = Severity::Warning,
#[cfg_attr(
    not(feature = "no-format-args-capture"),
    doc = r#"             "dividing by value ({y}) close to 0""#
)]
#[cfg_attr(
    feature = "no-format-args-capture",
    doc = r#"             "dividing by value ({}) close to 0", y"#
)]
///         );
///     }
///     Ok(x / y)
/// }
/// ```
#[macro_export]
macro_rules! bail {
    ($($key:ident = $value:expr,)* $fmt:literal $($arg:tt)*) => {
        return $crate::private::Err(
            $crate::miette!($($key = $value,)* $fmt $($arg)*)
        );
    };
    ($err:expr $(,)?) => {
        return $crate::private::Err($crate::miette!($err));
    };
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
///
/// Analogously to `assert!`, `ensure!` takes a condition and exits the function
/// if the condition fails. Unlike `assert!`, `ensure!` returns an `Error`
/// rather than panicking.
///
/// # Example
///
/// ```
/// # use miette::{ensure, Result};
/// #
/// # fn main() -> Result<()> {
/// #     let user = 0;
/// #
/// ensure!(user == 0, "only user 0 is allowed");
/// #     Ok(())
/// # }
/// ```
///
/// ```
/// # use miette::{ensure, Result};
/// # use thiserror::Error;
/// #
/// # const MAX_DEPTH: usize = 1;
/// #
/// #[derive(Error, Debug)]
/// enum ScienceError {
///     #[error("recursion limit exceeded")]
///     RecursionLimitExceeded,
///     # #[error("...")]
///     # More = (stringify! {
///     ...
///     # }, 1).1,
/// }
///
/// # fn main() -> Result<()> {
/// #     let depth = 0;
/// #
/// ensure!(depth <= MAX_DEPTH, ScienceError::RecursionLimitExceeded);
/// #     Ok(())
/// # }
/// ```
///
/// ```
/// use miette::{ensure, Result, Severity};
///
/// fn divide(x: f64, y: f64) -> Result<f64> {
///     ensure!(
///         y.abs() >= 1e-3,
///         severity = Severity::Warning,
#[cfg_attr(
    not(feature = "no-format-args-capture"),
    doc = r#"             "dividing by value ({y}) close to 0""#
)]
#[cfg_attr(
    feature = "no-format-args-capture",
    doc = r#"             "dividing by value ({}) close to 0", y"#
)]
///     );
///     Ok(x / y)
/// }
/// ```
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($key:ident = $value:expr,)* $fmt:literal $($arg:tt)*) => {
        if !$cond {
            return $crate::private::Err(
                $crate::miette!($($key = $value,)* $fmt $($arg)*)
            );
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return $crate::private::Err($crate::miette!($err));
        }
    };
}

/// Construct an ad-hoc [`Report`].
///
/// # Examples
///
/// With string literal and interpolation:
/// ```
/// # use miette::miette;
/// let x = 1;
/// let y = 2;
#[cfg_attr(
    not(feature = "no-format-args-capture"),
    doc = r#"let report = miette!("{x} + {} = {z}", y, z = x + y);"#
)]
#[cfg_attr(
    feature = "no-format-args-capture",
    doc = r#"let report = miette!("{} + {} = {z}", x, y, z = x + y);"#
)]
///
/// assert_eq!(report.to_string().as_str(), "1 + 2 = 3");
///
/// let z = x + y;
#[cfg_attr(
    not(feature = "no-format-args-capture"),
    doc = r#"let report = miette!("{x} + {y} = {z}");"#
)]
#[cfg_attr(
    feature = "no-format-args-capture",
    doc = r#"let report = miette!("{} + {} = {}", x, y, z);"#
)]
/// assert_eq!(report.to_string().as_str(), "1 + 2 = 3");
/// ```
///
/// With [`diagnostic!`]-like arguments:
/// ```
/// use miette::{miette, LabeledSpan, Severity};
///
/// let source = "(2 + 2".to_string();
/// let report = miette!(
///     // Those fields are optional
///     severity = Severity::Error,
///     code = "expected::rparen",
///     help = "always close your parens",
///     labels = vec![LabeledSpan::at_offset(6, "here")],
///     url = "https://example.com",
///     // Rest of the arguments are passed to `format!`
///     // to form diagnostic message
///     "expected closing ')'"
/// )
/// .with_source_code(source);
/// ```
///
/// ## `anyhow`/`eyre` Users
///
/// You can just replace `use`s of the `anyhow!`/`eyre!` macros with `miette!`.
///
/// [`diagnostic!`]: crate::diagnostic!
/// [`Report`]: crate::Report
#[macro_export]
macro_rules! miette {
    ($($key:ident = $value:expr,)* $fmt:literal $($arg:tt)*) => {
        $crate::Report::from(
            $crate::diagnostic!($($key = $value,)* $fmt $($arg)*)
        )
    };
    ($err:expr $(,)?) => ({
        use $crate::private::kind::*;
        let error = $err;
        (&error).miette_kind().new(error)
    });
}

/// Construct a [`MietteDiagnostic`] in more user-friendly way.
///
/// # Examples
/// ```
/// use miette::{diagnostic, LabeledSpan, Severity};
///
/// let source = "(2 + 2".to_string();
/// let diag = diagnostic!(
///     // Those fields are optional
///     severity = Severity::Error,
///     code = "expected::rparen",
///     help = "always close your parens",
///     labels = vec![LabeledSpan::at_offset(6, "here")],
///     url = "https://example.com",
///     // Rest of the arguments are passed to `format!`
///     // to form diagnostic message
///     "expected closing ')'",
/// );
/// ```
/// Diagnostic without any fields:
/// ```
/// # use miette::diagnostic;
/// let x = 1;
/// let y = 2;
///
#[cfg_attr(
    not(feature = "no-format-args-capture"),
    doc = r#" let diag = diagnostic!("{x} + {} = {z}", y, z = x + y);"#
)]
#[cfg_attr(
    feature = "no-format-args-capture",
    doc = r#" let diag = diagnostic!("{} + {} = {z}", x, y, z = x + y);"#
)]
/// assert_eq!(diag.message, "1 + 2 = 3");
///
/// let z = x + y;
#[cfg_attr(
    not(feature = "no-format-args-capture"),
    doc = r#"let diag = diagnostic!("{x} + {y} = {z}");"#
)]
#[cfg_attr(
    feature = "no-format-args-capture",
    doc = r#"let diag = diagnostic!("{} + {} = {}", x, y, z);"#
)]
/// assert_eq!(diag.message, "1 + 2 = 3");
/// ```
///
/// [`MietteDiagnostic`]: crate::MietteDiagnostic
#[macro_export]
macro_rules! diagnostic {
    ($fmt:literal $($arg:tt)*) => {{
        $crate::MietteDiagnostic::new(format!($fmt $($arg)*))
    }};
    ($($key:ident = $value:expr,)+ $fmt:literal $($arg:tt)*) => {{
        let mut diag = $crate::MietteDiagnostic::new(format!($fmt $($arg)*));
        $(diag.$key = Some($value.into());)*
        diag
    }};
}
