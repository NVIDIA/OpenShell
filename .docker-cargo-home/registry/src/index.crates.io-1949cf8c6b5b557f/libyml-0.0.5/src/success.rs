use core::ops::Deref;

/// Constant representing a successful operation.
pub const OK: Success = Success { ok: true };

/// Constant representing a failed operation.
pub const FAIL: Success = Success { ok: false };

/// Structure representing the success state of an operation.
#[must_use]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct Success {
    /// Boolean indicating whether the operation was successful.
    pub ok: bool,
}

/// Structure representing the failure state of an operation.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct Failure {
    /// Boolean indicating whether the operation failed.
    pub fail: bool,
}

impl Deref for Success {
    type Target = Failure;

    /// Returns a reference to the corresponding `Failure` instance based on the success state.
    fn deref(&self) -> &Self::Target {
        if self.ok {
            &Failure { fail: false }
        } else {
            &Failure { fail: true }
        }
    }
}

/// Checks if the given `Success` result indicates a successful operation.
///
/// # Arguments
///
/// * `result` - A `Success` struct representing the result of an operation.
///
/// # Returns
///
/// * `true` if the operation was successful.
/// * `false` if the operation failed.
pub fn is_success(result: Success) -> bool {
    result.ok
}

/// Checks if the given `Success` result indicates a failure operation.
///
/// # Arguments
///
/// * `result` - A `Success` struct representing the result of an operation.
///
/// # Returns
///
/// * `true` if the operation failed.
/// * `false` if the operation was successful.
pub fn is_failure(result: Success) -> bool {
    !result.ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_success() {
        assert!(is_success(OK));
        assert!(!is_success(FAIL));
    }

    #[test]
    fn test_deref() {
        let success = OK;
        let failure = FAIL;
        assert!(!success.deref().fail);
        assert!(failure.deref().fail);
    }
}
