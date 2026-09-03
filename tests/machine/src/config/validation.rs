// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use hex::FromHex;
use sha2::{Sha256, digest::Output};
use url::Url;

use super::{
    Error,
    schema::{Configuration, ImageManifest, MachineConfiguration},
};
use crate::virtual_machine::{
    VirtualMachineDefinition, VirtualMachineImageManifest, VirtualMachineImageManifests,
};

pub(super) fn validate(
    configuration: Configuration,
) -> Result<Vec<VirtualMachineDefinition>, Error> {
    if configuration.version != 1 {
        return Err(Error::UnsupportedConfigurationVersion(
            configuration.version,
        ));
    }

    configuration
        .machines
        .into_iter()
        .map(validate_machine)
        .collect()
}

fn validate_machine(
    configuration: MachineConfiguration,
) -> Result<VirtualMachineDefinition, Error> {
    if configuration.name.trim().is_empty() {
        return Err(Error::EmptyMachineName);
    }

    let amd64 = validate_image_manifest(&configuration.images.amd64)?;
    let arm64 = validate_image_manifest(&configuration.images.arm64)?;

    Ok(VirtualMachineDefinition {
        name: configuration.name,
        images: VirtualMachineImageManifests { amd64, arm64 },
    })
}

fn validate_image_manifest(manifest: &ImageManifest) -> Result<VirtualMachineImageManifest, Error> {
    let url = Url::parse(&manifest.url)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::UnsupportedImageUrlScheme(url.scheme().to_owned()));
    }

    let sha256 = <[u8; 32]>::from_hex(manifest.sha256.as_bytes())?;

    Ok(VirtualMachineImageManifest {
        url,
        sha256: Output::<Sha256>::from(sha256),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Images;

    const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_valid_configuration() {
        let result = validate(configuration(
            "test-machine",
            manifest("https://example.com/amd64.img", VALID_SHA256),
            manifest("http://example.com/arm64.img", VALID_SHA256),
        ));

        assert!(result.is_ok());
    }

    #[test]
    fn rejects_unsupported_configuration_version() {
        let mut configuration = configuration(
            "test-machine",
            manifest("https://example.com/amd64.img", VALID_SHA256),
            manifest("https://example.com/arm64.img", VALID_SHA256),
        );
        configuration.version = 2;

        let result = validate(configuration);

        assert!(matches!(
            result,
            Err(Error::UnsupportedConfigurationVersion(2))
        ));
    }

    #[test]
    fn rejects_empty_machine_name() {
        for name in ["", " \t\n"] {
            let result = validate(configuration(
                name,
                manifest("https://example.com/amd64.img", VALID_SHA256),
                manifest("https://example.com/arm64.img", VALID_SHA256),
            ));

            assert!(matches!(result, Err(Error::EmptyMachineName)));
        }
    }

    #[test]
    fn rejects_unsupported_image_url_scheme() {
        let result = validate(configuration(
            "test-machine",
            manifest("file:///tmp/amd64.img", VALID_SHA256),
            manifest("https://example.com/arm64.img", VALID_SHA256),
        ));

        assert!(matches!(
            result,
            Err(Error::UnsupportedImageUrlScheme(scheme)) if scheme == "file"
        ));
    }

    #[test]
    fn rejects_invalid_sha256() {
        for sha256 in ["not-hex", "00"] {
            let result = validate(configuration(
                "test-machine",
                manifest("https://example.com/amd64.img", sha256),
                manifest("https://example.com/arm64.img", VALID_SHA256),
            ));

            assert!(matches!(result, Err(Error::InvalidSha256(_))));
        }
    }

    fn configuration(name: &str, amd64: ImageManifest, arm64: ImageManifest) -> Configuration {
        Configuration {
            version: 1,
            machines: vec![MachineConfiguration {
                name: name.to_owned(),
                images: Images { arm64, amd64 },
            }],
        }
    }

    fn manifest(url: &str, sha256: &str) -> ImageManifest {
        ImageManifest {
            url: url.to_owned(),
            sha256: sha256.to_owned(),
        }
    }
}
