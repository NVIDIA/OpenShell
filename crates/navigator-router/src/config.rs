use serde::Deserialize;
use std::path::Path;

use crate::RouterError;

#[derive(Debug, Clone, Deserialize)]
pub struct RouterConfig {
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub routing_hint: String,
    pub endpoint: String,
    pub model: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    pub routing_hint: String,
    pub endpoint: String,
    pub model: String,
    pub api_key: String,
}

impl RouterConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, RouterError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            RouterError::Internal(format!(
                "failed to read router config {}: {e}",
                path.display()
            ))
        })?;
        let config: Self = toml::from_str(&content).map_err(|e| {
            RouterError::Internal(format!(
                "failed to parse router config {}: {e}",
                path.display()
            ))
        })?;
        config.resolve()
    }

    fn resolve(self) -> Result<Self, RouterError> {
        // Validate that all routes can resolve their API keys
        for route in &self.routes {
            route.resolve_api_key()?;
        }
        Ok(self)
    }

    pub fn resolve_routes(&self) -> Result<Vec<ResolvedRoute>, RouterError> {
        self.routes.iter().map(RouteConfig::resolve).collect()
    }
}

impl RouteConfig {
    fn resolve_api_key(&self) -> Result<String, RouterError> {
        if let Some(key) = &self.api_key {
            return Ok(key.clone());
        }
        if let Some(env_var) = &self.api_key_env {
            return std::env::var(env_var).map_err(|_| {
                RouterError::Internal(format!(
                    "environment variable {env_var} not set for route '{}'",
                    self.routing_hint
                ))
            });
        }
        Err(RouterError::Internal(format!(
            "route '{}' has neither api_key nor api_key_env",
            self.routing_hint
        )))
    }

    fn resolve(&self) -> Result<ResolvedRoute, RouterError> {
        Ok(ResolvedRoute {
            routing_hint: self.routing_hint.clone(),
            endpoint: self.endpoint.clone(),
            model: self.model.clone(),
            api_key: self.resolve_api_key()?,
        })
    }
}
