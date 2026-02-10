pub const DEFAULT_IMAGE_NAME: &str = "navigator-cluster";
pub const NETWORK_NAME: &str = "navigator-cluster";
pub const KUBECONFIG_PATH: &str = "/etc/rancher/k3s/k3s.yaml";
pub const CLI_SECRET_NAME: &str = "navigator-cli-client";
pub const NAV_GATEWAY_TLS_ENABLED_ENV: &str = "NAV_GATEWAY_TLS_ENABLED";
pub const HELMCHART_MANIFEST_PATHS: [&str; 2] = [
    "/var/lib/rancher/k3s/server/manifests/navigator-helmchart.yaml",
    "/opt/navigator/manifests/navigator-helmchart.yaml",
];

pub fn container_name(name: &str) -> String {
    format!("navigator-cluster-{name}")
}

pub fn volume_name(name: &str) -> String {
    format!("navigator-cluster-{name}")
}
