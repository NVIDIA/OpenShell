// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Account-file contents used to label a resolved numeric workload identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountFiles {
    pub group: String,
    pub passwd: String,
}

/// Names and IDs to reconcile into account files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountReconciliation<'a> {
    pub gid: u32,
    pub group_name: &'a str,
    pub uid: u32,
    pub user_alias: Option<&'a str>,
    pub user_name: &'a str,
}

impl<'a> AccountReconciliation<'a> {
    /// Build an account reconciliation request from a driver spec.
    ///
    /// # Errors
    ///
    /// Returns an error when the trusted username is not a valid account name.
    pub fn from_driver_spec(
        spec: &'a crate::proto::compute::v1::DriverSandboxSpec,
        uid: u32,
        gid: u32,
    ) -> Result<Self, String> {
        let user_name = match spec.sandbox_username.as_str() {
            "" => "sandbox",
            user_name => user_name,
        };
        if !valid_account_name(user_name) {
            return Err(format!("invalid sandbox account name '{user_name}'"));
        }

        let process = spec
            .policy
            .as_ref()
            .and_then(|policy| policy.process.as_ref());
        let group_name = process
            .map(|process| process.run_as_group.as_str())
            .filter(|name| !name.is_empty() && name.parse::<u32>().is_err())
            .unwrap_or(user_name);
        let user_alias = process
            .map(|process| process.run_as_user.as_str())
            .filter(|name| !name.is_empty() && name.parse::<u32>().is_err() && *name != user_name);

        Ok(Self {
            gid,
            group_name,
            uid,
            user_alias,
            user_name,
        })
    }
}

impl AccountFiles {
    /// Parse account files as UTF-8.
    ///
    /// # Errors
    ///
    /// Returns an error when either file is not valid UTF-8.
    pub fn new(passwd: Vec<u8>, group: Vec<u8>) -> Result<Self, String> {
        let group = String::from_utf8(group)
            .map_err(|error| format!("image /etc/group is not UTF-8: {error}"))?;
        let passwd = String::from_utf8(passwd)
            .map_err(|error| format!("image /etc/passwd is not UTF-8: {error}"))?;

        Ok(Self { group, passwd })
    }

    /// Reconcile names without changing the resolved numeric identity.
    #[must_use]
    pub fn reconcile(mut self, request: AccountReconciliation<'_>) -> Self {
        self.rewrite_group(request);
        self.rewrite_passwd(request);
        self
    }

    fn rewrite_group(&mut self, request: AccountReconciliation<'_>) {
        let gid = request.gid.to_string();
        let mut found = false;
        let mut lines = Vec::new();
        let terminated = self.group.ends_with('\n');
        let target_exists = self.group.lines().any(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            matches!(
                fields.as_slice(),
                [name, _, _, _, ..] if *name == request.group_name
            )
        });

        for line in self.group.lines() {
            let fields = line.split(':').collect::<Vec<_>>();
            let [name, pass, entry_gid, members, ..] = fields.as_slice() else {
                lines.push(line.to_string());
                continue;
            };

            if *name == request.group_name {
                if !found {
                    lines.push(format!("{}:{pass}:{gid}:{members}", request.group_name));
                    found = true;
                }

                continue;
            }

            let legacy = request.group_name != "sandbox" && *name == "sandbox";

            if *entry_gid == gid || legacy {
                if !target_exists && !found {
                    lines.push(format!("{}:x:{gid}:", request.group_name));
                    found = true;
                }

                continue;
            }
            lines.push(line.to_string());
        }

        if !found {
            lines.push(format!("{}:x:{gid}:", request.group_name));
        }

        self.group = lines.join("\n");
        if terminated || !found {
            self.group.push('\n');
        }
    }

    fn rewrite_passwd(&mut self, request: AccountReconciliation<'_>) {
        let gid = request.gid.to_string();
        let uid = request.uid.to_string();
        let mut alias = None;
        let mut found = false;
        let mut lines = Vec::new();
        let terminated = self.passwd.ends_with('\n');
        let target_exists = self.passwd.lines().any(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            matches!(
                fields.as_slice(),
                [name, _, _, _, _, _, _, ..] if *name == request.user_name
            )
        });

        for line in self.passwd.lines() {
            let fields = line.split(':').collect::<Vec<_>>();
            let [name, pass, entry_uid, _, gecos, home, shell, ..] = fields.as_slice() else {
                lines.push(line.to_string());
                continue;
            };

            if Some(*name) == request.user_alias {
                alias = Some(format!("{name}:{pass}:{uid}:{gid}:{gecos}:{home}:{shell}"));

                continue;
            }

            if *name == request.user_name {
                if !found {
                    lines.push(format!(
                        "{}:{pass}:{uid}:{gid}:{gecos}:{home}:{shell}",
                        request.user_name
                    ));
                    found = true;
                }

                continue;
            }

            let legacy = request.user_name != "sandbox" && *name == "sandbox";

            if *entry_uid == uid || legacy {
                if !target_exists && !found {
                    lines.push(format!(
                        "{}:x:{uid}:{gid}::/sandbox:/bin/sh",
                        request.user_name
                    ));
                    found = true;
                }

                continue;
            }
            lines.push(line.to_string());
        }

        if !found {
            lines.push(format!(
                "{}:x:{uid}:{gid}::/sandbox:/bin/sh",
                request.user_name
            ));
        }
        if let Some(alias) = alias {
            lines.push(alias);
        }

        self.passwd = lines.join("\n");
        if terminated || !found {
            self.passwd.push('\n');
        }
    }
}

/// Return whether a name is safe for POSIX account files.
#[must_use]
pub fn valid_account_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    name != "root"
        && name.len() <= 256
        && (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '$')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_reconciliation_request_defaults_to_sandbox() {
        let spec = crate::proto::compute::v1::DriverSandboxSpec::default();

        let act = AccountReconciliation::from_driver_spec(&spec, 1000, 1001).unwrap();

        assert_eq!(
            act,
            AccountReconciliation {
                gid: 1001,
                group_name: "sandbox",
                uid: 1000,
                user_alias: None,
                user_name: "sandbox",
            }
        );
    }

    #[test]
    fn account_reconciliation_request_keeps_policy_aliases() {
        let spec = crate::proto::compute::v1::DriverSandboxSpec {
            policy: Some(crate::proto::SandboxPolicy {
                process: Some(crate::proto::ProcessPolicy {
                    run_as_group: "agents".to_string(),
                    run_as_user: "ubuntu".to_string(),
                }),
                ..Default::default()
            }),
            sandbox_username: "ebusto".to_string(),
            ..Default::default()
        };

        let act = AccountReconciliation::from_driver_spec(&spec, 1000, 1001).unwrap();

        assert_eq!(
            act,
            AccountReconciliation {
                gid: 1001,
                group_name: "agents",
                uid: 1000,
                user_alias: Some("ubuntu"),
                user_name: "ebusto",
            }
        );
    }

    #[test]
    fn account_reconciliation_request_rewrites_default_account() {
        let files = AccountFiles::new(
            b"root:x:0:0:root:/root:/bin/sh\nubuntu:x:1000:1001::/home/ubuntu:/bin/sh\n".to_vec(),
            b"root:x:0:\nubuntu:x:1001:\n".to_vec(),
        )
        .unwrap();
        let spec = crate::proto::compute::v1::DriverSandboxSpec::default();
        let request = AccountReconciliation::from_driver_spec(&spec, 1000, 1001).unwrap();

        let act = files.reconcile(request);
        let exp = AccountFiles {
            group: "root:x:0:\nsandbox:x:1001:\n".to_string(),
            passwd: concat!(
                "root:x:0:0:root:/root:/bin/sh\n",
                "sandbox:x:1000:1001::/sandbox:/bin/sh\n",
            )
            .to_string(),
        };

        assert_eq!(act, exp);
    }

    #[test]
    fn reconcile_uses_configured_names_and_preserves_alias() {
        let files = AccountFiles::new(
            b"root:x:0:0:root:/root:/bin/sh\nubuntu:x:1000:1000::/home/ubuntu:/bin/sh\n".to_vec(),
            b"root:x:0:\nubuntu:x:1000:\n".to_vec(),
        )
        .unwrap();

        let act = files.reconcile(AccountReconciliation {
            gid: 1000,
            group_name: "ebusto",
            uid: 1000,
            user_alias: Some("ubuntu"),
            user_name: "ebusto",
        });

        assert!(act.group.contains("ebusto:x:1000:"));
        assert!(act.passwd.contains("ebusto:x:1000:1000::/sandbox:/bin/sh"));
        assert!(
            act.passwd
                .contains("ubuntu:x:1000:1000::/home/ubuntu:/bin/sh")
        );
    }

    #[test]
    fn valid_account_name_rejects_root_and_unsafe_names() {
        assert!(valid_account_name("ebusto"));
        assert!(!valid_account_name("root"));
        assert!(!valid_account_name("bad:name"));
        assert!(!valid_account_name("9user"));
    }
}
