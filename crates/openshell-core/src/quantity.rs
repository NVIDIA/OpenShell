// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared Kubernetes-style CPU and memory quantity validation.
//!
//! `field_name` identifies the field in error messages (e.g. `--cpu` for the
//! CLI or `spec.resource_requirements.cpu.limit` for the gateway), so both
//! callers can present the same validation errors in their own idiom.

/// Validate a Kubernetes-style CPU quantity string (e.g. "500m", "2", "0.5").
///
/// # Errors
/// Returns a human-readable error message when the value is empty,
/// malformed, or not greater than zero.
pub fn validate_cpu_quantity(value: &str, field_name: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }

    if let Some(millicores) = value.strip_suffix('m') {
        if millicores.is_empty() || !millicores.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!(
                "invalid {field_name} value '{value}': expected positive cores or millicores, for example 2, 0.5, or 500m"
            ));
        }
        let millicores = millicores.parse::<u64>().map_err(|_| {
            format!(
                "invalid {field_name} value '{value}': expected positive cores or millicores, for example 2, 0.5, or 500m"
            )
        })?;
        if millicores == 0 {
            return Err(format!("{field_name} must be greater than zero"));
        }
        return Ok(());
    }

    let cores = value.parse::<f64>().map_err(|_| {
        format!(
            "invalid {field_name} value '{value}': expected positive cores or millicores, for example 2, 0.5, or 500m"
        )
    })?;
    if !cores.is_finite() || cores <= 0.0 {
        return Err(format!("{field_name} must be greater than zero"));
    }
    Ok(())
}

/// Validate a Kubernetes-style memory quantity string (e.g. "512Mi", "4Gi", "8G").
///
/// # Errors
/// Returns a human-readable error message when the value is empty,
/// malformed, or not greater than zero.
pub fn validate_memory_quantity(value: &str, field_name: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }

    let number_end = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(number_end);
    if number.is_empty()
        || !matches!(
            suffix,
            "" | "Ki" | "Mi" | "Gi" | "Ti" | "Pi" | "Ei" | "K" | "M" | "G" | "T" | "P" | "E"
        )
    {
        return Err(format!(
            "invalid {field_name} value '{value}': expected positive bytes or a quantity such as 512Mi, 4Gi, or 8G"
        ));
    }

    let amount = number.parse::<u128>().map_err(|_| {
        format!(
            "invalid {field_name} value '{value}': expected positive bytes or a quantity such as 512Mi, 4Gi, or 8G"
        )
    })?;
    if amount == 0 {
        return Err(format!("{field_name} must be greater than zero"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_cpu_quantity_accepts_cores_and_millicores() {
        assert!(validate_cpu_quantity("2", "--cpu").is_ok());
        assert!(validate_cpu_quantity("0.5", "--cpu").is_ok());
        assert!(validate_cpu_quantity("500m", "--cpu").is_ok());
    }

    #[test]
    fn validate_cpu_quantity_rejects_zero_and_malformed() {
        assert!(validate_cpu_quantity("", "--cpu").is_err());
        assert!(validate_cpu_quantity("0", "--cpu").is_err());
        assert!(validate_cpu_quantity("0m", "--cpu").is_err());
        assert!(validate_cpu_quantity("abc", "--cpu").is_err());
        assert!(validate_cpu_quantity("-1", "--cpu").is_err());
    }

    #[test]
    fn validate_memory_quantity_accepts_known_suffixes() {
        assert!(validate_memory_quantity("512Mi", "--memory").is_ok());
        assert!(validate_memory_quantity("4Gi", "--memory").is_ok());
        assert!(validate_memory_quantity("8G", "--memory").is_ok());
        assert!(validate_memory_quantity("1024", "--memory").is_ok());
    }

    #[test]
    fn validate_memory_quantity_rejects_zero_and_malformed() {
        assert!(validate_memory_quantity("", "--memory").is_err());
        assert!(validate_memory_quantity("0Gi", "--memory").is_err());
        assert!(validate_memory_quantity("4Xi", "--memory").is_err());
        assert!(validate_memory_quantity("Gi", "--memory").is_err());
    }
}
