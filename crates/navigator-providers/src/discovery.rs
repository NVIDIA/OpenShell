use crate::{DiscoveredProvider, DiscoveryContext, ProviderDiscoverySpec, ProviderError};
use serde_json::Value;

pub fn discover_with_spec(
    spec: &ProviderDiscoverySpec,
    context: &dyn DiscoveryContext,
) -> Result<Option<DiscoveredProvider>, ProviderError> {
    let mut discovered = DiscoveredProvider::default();

    for key in spec.credential_env_vars {
        if let Some(value) = context.env_var(key)
            && !value.trim().is_empty()
        {
            discovered
                .credentials
                .entry((*key).to_string())
                .or_insert(value);
        }
    }

    for raw_path in spec.config_paths {
        let Some(path) = context.expand_home(raw_path) else {
            continue;
        };
        if !context.path_exists(&path) {
            continue;
        }

        if let Some(ext) = path.extension().and_then(|ext| ext.to_str())
            && ext.eq_ignore_ascii_case("json")
        {
            let contents = context.read_to_string(&path).unwrap_or_default();
            if contents.trim().is_empty() {
                continue;
            }

            let value: Value =
                serde_json::from_str(&contents).map_err(|err| ProviderError::ParseJson {
                    path: path.display().to_string(),
                    message: err.to_string(),
                })?;

            collect_credential_fields(&value, "", &mut discovered.credentials);
        }
    }

    if discovered.is_empty() {
        Ok(None)
    } else {
        Ok(Some(discovered))
    }
}

fn looks_like_credential_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    ["api_key", "apikey", "token", "secret", "password", "auth"]
        .iter()
        .any(|needle| normalized.contains(needle))
}

fn collect_credential_fields(
    value: &Value,
    prefix: &str,
    credentials: &mut std::collections::HashMap<String, String>,
) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };

                if let Some(raw) = nested.as_str()
                    && !raw.trim().is_empty()
                    && looks_like_credential_key(key)
                {
                    credentials
                        .entry(path.clone())
                        .or_insert_with(|| raw.to_string());
                }

                collect_credential_fields(nested, &path, credentials);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_credential_fields(item, prefix, credentials);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::discover_with_spec;
    use crate::ProviderDiscoverySpec;
    use crate::test_helpers::{MockDiscoveryContext, home_join};

    #[test]
    fn ignores_home_escaping_config_paths() {
        let spec = ProviderDiscoverySpec {
            id: "test",
            credential_env_vars: &[],
            config_paths: &["~/../secrets.json"],
        };

        let ctx = MockDiscoveryContext::new()
            .with_home("/mock/home")
            .with_file(
                home_join("/mock/home", "../secrets.json"),
                r#"{"token":"secret"}"#,
            );

        let discovered = discover_with_spec(&spec, &ctx).expect("discovery");
        assert!(discovered.is_none());
    }
}
