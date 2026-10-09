// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Lifecycle-owned inbound authorization for the unpackaged `AppContainer` peer.
//! COM objects stay on the initializing thread; the owner stores only a name.

#![allow(unsafe_code)]

use std::io;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule3, NET_FW_ACTION_ALLOW, NET_FW_IP_PROTOCOL_TCP,
    NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::core::BSTR;

struct ComApartment;
impl ComApartment {
    fn new() -> windows::core::Result<Self> {
        // SAFETY: initialization/uninitialization are paired on this thread.
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
        }
        Ok(Self)
    }
}
impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: new() successfully initialized COM on the same thread.
        unsafe { CoUninitialize() };
    }
}

fn error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!(
        "MXC proxy peer firewall authorization failed: {error}. Proxy-peer mode requires \
         permission to manage Windows Firewall rules; run the gateway with that permission \
         and allow local inbound rules in the active firewall profiles. \
         The gateway will create only a loopback TCP rule for this peer executable, \
         AppContainer SID and listener port."
    ))
}

fn configured_rule(
    name: &str,
    exe: &str,
    sid: &str,
    port: u16,
) -> windows::core::Result<INetFwRule3> {
    // SAFETY: COM is initialized by the caller and all BSTR inputs are owned.
    unsafe {
        let rule: INetFwRule3 = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        rule.SetName(&BSTR::from(name))?;
        rule.SetApplicationName(&BSTR::from(exe))?;
        rule.SetLocalAppPackageId(&BSTR::from(sid))?;
        // Protocol must be set before the port properties.
        rule.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0)?;
        rule.SetLocalPorts(&BSTR::from(port.to_string()))?;
        rule.SetLocalAddresses(&BSTR::from("127.0.0.1"))?;
        rule.SetRemoteAddresses(&BSTR::from("127.0.0.1"))?;
        rule.SetDirection(NET_FW_RULE_DIR_IN)?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
        rule.SetAction(NET_FW_ACTION_ALLOW)?;
        rule.SetEdgeTraversal(false.into())?;
        rule.SetEnabled(true.into())?;
        Ok(rule)
    }
}

/// A unique rule owned by a single peer. No COM interface crosses threads.
pub struct PeerFirewallRule {
    name: String,
}
impl PeerFirewallRule {
    pub fn install(name: String, exe: &str, sid: &str, port: u16) -> io::Result<Self> {
        let _apartment = ComApartment::new().map_err(error)?;
        // SAFETY: COM is initialized on this thread. This changes only one
        // new rule; it never changes profile defaults or loopback exemptions.
        unsafe {
            let policy: INetFwPolicy2 =
                CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER).map_err(error)?;
            if policy.LocalPolicyModifyState().map_err(error)? != NET_FW_MODIFY_STATE_OK {
                return Err(error(
                    "local firewall rules are overridden or inbound traffic is blocked",
                ));
            }
            let profiles = policy.CurrentProfileTypes().map_err(error)?;
            for profile in [
                NET_FW_PROFILE2_DOMAIN,
                NET_FW_PROFILE2_PRIVATE,
                NET_FW_PROFILE2_PUBLIC,
            ] {
                if profiles & profile.0 != 0
                    && policy
                        .get_BlockAllInboundTraffic(profile)
                        .map_err(error)?
                        .as_bool()
                {
                    return Err(error("an active firewall profile blocks all inbound rules"));
                }
            }
            let rule = configured_rule(&name, exe, sid, port).map_err(error)?;
            policy.Rules().map_err(error)?.Add(&rule).map_err(error)?;
        }
        Ok(Self { name })
    }
}
impl Drop for PeerFirewallRule {
    fn drop(&mut self) {
        let result = (|| -> windows::core::Result<()> {
            let _apartment = ComApartment::new()?;
            // SAFETY: COM is initialized; remove only this owner's random name.
            unsafe {
                let policy: INetFwPolicy2 =
                    CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?;
                policy.Rules()?.Remove(&BSTR::from(&self.name))
            }
        })();
        if let Err(error) = result {
            tracing::warn!(rule = %self.name, %error, "failed to remove MXC proxy peer firewall rule");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_install_has_explicit_permission_failure_or_owned_cleanup() {
        let name = format!("OpenShell MXC peer test-{}", uuid::Uuid::new_v4());
        let result = PeerFirewallRule::install(
            name.clone(),
            r"C:\peer.exe",
            "S-1-15-2-123456789-234567890-345678901-456789012-567890123-678901234-789012345",
            54321,
        );
        match result {
            Ok(rule) => {
                let _apartment = ComApartment::new().unwrap();
                // SAFETY: the apartment and collection are live on this thread.
                unsafe {
                    let policy: INetFwPolicy2 =
                        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER).unwrap();
                    assert!(policy.Rules().unwrap().Item(&BSTR::from(&name)).is_ok());
                    drop(rule);
                    assert!(policy.Rules().unwrap().Item(&BSTR::from(&name)).is_err());
                }
                eprintln!("EVIDENCE: native firewall install and removal succeeded");
            }
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("permission to manage Windows Firewall rules"),
                    "{message}"
                );
                assert!(
                    message.contains("0x80070005"),
                    "expected a permission denial on a standard token: {message}"
                );
                let _apartment = ComApartment::new().unwrap();
                // SAFETY: read-only lookup after failed installation.
                unsafe {
                    let policy: INetFwPolicy2 =
                        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER).unwrap();
                    assert!(policy.Rules().unwrap().Item(&BSTR::from(&name)).is_err());
                }
                eprintln!(
                    "EVIDENCE: native firewall permission denial was actionable and left no rule"
                );
            }
        }
    }

    #[test]
    fn peer_rule_is_scoped_to_identity_executable_and_loopback_port() {
        let _apartment = ComApartment::new().unwrap();
        let rule = configured_rule(
            "test-no-install",
            r"C:\peer.exe",
            "S-1-15-2-123456789-234567890-345678901-456789012-567890123-678901234-789012345",
            54321,
        )
        .unwrap();
        // Inspect the actual COM rule object without installing a host rule.
        // SAFETY: object and apartment are live on this thread.
        unsafe {
            assert_eq!(rule.ApplicationName().unwrap().to_string(), r"C:\peer.exe");
            assert_eq!(
                rule.LocalAppPackageId().unwrap().to_string(),
                "S-1-15-2-123456789-234567890-345678901-456789012-567890123-678901234-789012345"
            );
            assert_eq!(rule.Protocol().unwrap(), NET_FW_IP_PROTOCOL_TCP.0);
            assert_eq!(rule.LocalPorts().unwrap().to_string(), "54321");
            assert_eq!(
                rule.LocalAddresses().unwrap().to_string(),
                "127.0.0.1/255.255.255.255"
            );
            assert_eq!(
                rule.RemoteAddresses().unwrap().to_string(),
                "127.0.0.1/255.255.255.255"
            );
            assert_eq!(rule.Direction().unwrap(), NET_FW_RULE_DIR_IN);
            assert_eq!(rule.Action().unwrap(), NET_FW_ACTION_ALLOW);
            assert_eq!(rule.Profiles().unwrap(), NET_FW_PROFILE2_ALL.0);
            assert!(rule.Enabled().unwrap().as_bool());
            assert!(!rule.EdgeTraversal().unwrap().as_bool());
        }
    }
}
