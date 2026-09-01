// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

const SHA1_HEX_LEN: usize = 40;
const ZERO_SHA1: &str = "0000000000000000000000000000000000000000";

pub struct GitSigner {
    signing_key: PathBuf,
}

pub struct SignedPush {
    pub body: Vec<u8>,
    pub signed_commits: u32,
}

#[derive(Debug)]
pub struct SignError {
    message: String,
}

impl SignError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn public_message(&self) -> &'static str {
        "outgoing Git push could not be signed"
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SignError {}

impl GitSigner {
    pub fn new(signing_key: PathBuf) -> Result<Self, String> {
        if !signing_key.is_file() {
            return Err("the signing key must name a readable file".into());
        }
        Ok(Self { signing_key })
    }

    pub fn sign_receive_pack(
        &self,
        body: &[u8],
        upstream_url: Option<&str>,
    ) -> Result<SignedPush, SignError> {
        let mut parsed = ReceivePackRequest::parse(body)?;
        if parsed.updates.is_empty() {
            return Err(SignError::new(
                "receive-pack request contains no ref updates",
            ));
        }

        let workspace = TempDir::new().map_err(|error| SignError::new(error.to_string()))?;
        let repo = workspace.path().join("objects.git");
        run_git(None, &["init", "--bare", repo_string(&repo)?], None)?;
        if let Some(upstream_url) = upstream_url {
            hydrate_upstream(&repo, upstream_url, &parsed.updates)?;
        }
        run_git(
            Some(&repo),
            &["index-pack", "--stdin", "--fix-thin"],
            Some(parsed.pack),
        )?;

        let mut commit_ids = HashSet::new();
        for update in &parsed.updates {
            if update.new_oid == ZERO_SHA1 {
                continue;
            }
            let output = run_git(
                Some(&repo),
                &["rev-list", &update.new_oid, "--not", "--all"],
                None,
            )?;
            let output = String::from_utf8(output)
                .map_err(|_| SignError::new("git returned a non-UTF-8 commit list"))?;
            commit_ids.extend(output.lines().map(str::to_string));
        }
        let mut rewriter = CommitRewriter {
            repo: &repo,
            signing_key: &self.signing_key,
            commit_ids,
            rewritten: HashMap::new(),
            active: HashSet::new(),
            signed_count: 0,
            workspace: workspace.path(),
        };

        for update in &mut parsed.updates {
            if update.new_oid == ZERO_SHA1 {
                continue;
            }
            if !update.ref_name.starts_with("refs/heads/") {
                return Err(SignError::new(
                    "prototype supports direct branch updates only",
                ));
            }
            if !rewriter.commit_ids.contains(&update.new_oid) {
                return Err(SignError::new(
                    "branch tip commit is not self-contained in the push pack",
                ));
            }
            update.new_oid = rewriter.rewrite(&update.new_oid)?;
        }

        if rewriter.signed_count == 0 {
            return Err(SignError::new(
                "receive-pack request contains no commits to sign",
            ));
        }

        let base_oids = list_ref_oids(&repo, "refs/middleware")?;
        let mut revisions = parsed
            .updates
            .iter()
            .filter(|update| update.new_oid != ZERO_SHA1)
            .map(|update| update.new_oid.clone())
            .collect::<Vec<_>>();
        revisions.extend(base_oids.into_iter().map(|oid| format!("^{oid}")));
        let revision_input = revisions.join("\n") + "\n";
        let replacement_pack = run_git(
            Some(&repo),
            &["pack-objects", "--stdout", "--revs", "--thin"],
            Some(revision_input.as_bytes()),
        )?;

        let mut result = parsed.prefix.to_vec();
        for update in &parsed.updates {
            result[update.new_oid_range.clone()].copy_from_slice(update.new_oid.as_bytes());
        }
        result.extend_from_slice(&replacement_pack);
        Ok(SignedPush {
            body: result,
            signed_commits: rewriter.signed_count,
        })
    }
}

struct ReceivePackRequest<'a> {
    prefix: &'a [u8],
    pack: &'a [u8],
    updates: Vec<RefUpdate>,
}

struct RefUpdate {
    old_oid: String,
    new_oid: String,
    ref_name: String,
    new_oid_range: std::ops::Range<usize>,
}

impl<'a> ReceivePackRequest<'a> {
    fn parse(body: &'a [u8]) -> Result<Self, SignError> {
        let mut updates = Vec::new();
        let mut offset = 0;
        let mut command_section = true;
        let pack_offset = loop {
            if !command_section && body[offset..].starts_with(b"PACK") {
                break offset;
            }
            if offset + 4 > body.len() {
                return Err(SignError::new("receive-pack request has no packfile"));
            }

            let length = parse_pkt_length(&body[offset..offset + 4])?;
            if length == 0 {
                offset += 4;
                command_section = false;
                continue;
            }
            if length < 4 || offset + length > body.len() {
                return Err(SignError::new("invalid receive-pack pkt-line length"));
            }
            if !command_section {
                // Push options, when negotiated, are pkt-lines between the
                // command flush and the packfile. Preserve them unchanged.
                offset += length;
                continue;
            }
            let payload_start = offset + 4;
            let payload = &body[payload_start..offset + length];
            let command = payload.split(|byte| *byte == 0).next().unwrap_or(payload);
            let command = command.strip_suffix(b"\n").unwrap_or(command);
            let first_space = command
                .iter()
                .position(|byte| *byte == b' ')
                .ok_or_else(|| SignError::new("invalid receive-pack ref command"))?;
            let second_space = command[first_space + 1..]
                .iter()
                .position(|byte| *byte == b' ')
                .map(|index| first_space + 1 + index)
                .ok_or_else(|| SignError::new("invalid receive-pack ref command"))?;
            if first_space != SHA1_HEX_LEN || second_space - first_space - 1 != SHA1_HEX_LEN {
                return Err(SignError::new(
                    "prototype supports SHA-1 Git repositories only",
                ));
            }
            let new_start = payload_start + first_space + 1;
            let old_oid = ascii_oid(&body[payload_start..payload_start + SHA1_HEX_LEN])?;
            let new_oid = ascii_oid(&body[new_start..new_start + SHA1_HEX_LEN])?;
            let ref_name = std::str::from_utf8(&command[second_space + 1..])
                .map_err(|_| SignError::new("receive-pack ref name is not UTF-8"))?
                .to_string();
            updates.push(RefUpdate {
                old_oid,
                new_oid,
                ref_name,
                new_oid_range: new_start..new_start + SHA1_HEX_LEN,
            });
            offset += length;
        };

        Ok(Self {
            prefix: &body[..pack_offset],
            pack: &body[pack_offset..],
            updates,
        })
    }
}

fn hydrate_upstream(
    repo: &Path,
    upstream_url: &str,
    updates: &[RefUpdate],
) -> Result<(), SignError> {
    run_git(
        Some(repo),
        &[
            "-c",
            "credential.interactive=false",
            "fetch",
            "--no-tags",
            "--depth=1",
            upstream_url,
            "+HEAD:refs/middleware/upstream-head",
        ],
        None,
    )?;
    for (index, old_oid) in updates
        .iter()
        .map(|update| update.old_oid.as_str())
        .filter(|oid| *oid != ZERO_SHA1)
        .collect::<HashSet<_>>()
        .into_iter()
        .enumerate()
    {
        let destination = format!("+{old_oid}:refs/middleware/base-{index}");
        run_git(
            Some(repo),
            &[
                "-c",
                "credential.interactive=false",
                "fetch",
                "--no-tags",
                "--depth=1",
                upstream_url,
                &destination,
            ],
            None,
        )?;
    }
    Ok(())
}

fn list_ref_oids(repo: &Path, prefix: &str) -> Result<Vec<String>, SignError> {
    let output = run_git(
        Some(repo),
        &["for-each-ref", "--format=%(objectname)", prefix],
        None,
    )?;
    let output = String::from_utf8(output)
        .map_err(|_| SignError::new("git returned a non-UTF-8 ref list"))?;
    Ok(output.lines().map(str::to_string).collect())
}

fn parse_pkt_length(bytes: &[u8]) -> Result<usize, SignError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| SignError::new("pkt-line length is not ASCII"))?;
    usize::from_str_radix(text, 16).map_err(|_| SignError::new("invalid pkt-line length"))
}

fn ascii_oid(bytes: &[u8]) -> Result<String, SignError> {
    if bytes.len() != SHA1_HEX_LEN || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(SignError::new("invalid SHA-1 object id"));
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| SignError::new("invalid SHA-1 object id"))
}

struct CommitRewriter<'a> {
    repo: &'a Path,
    signing_key: &'a Path,
    commit_ids: HashSet<String>,
    rewritten: HashMap<String, String>,
    active: HashSet<String>,
    signed_count: u32,
    workspace: &'a Path,
}

impl CommitRewriter<'_> {
    fn rewrite(&mut self, oid: &str) -> Result<String, SignError> {
        if let Some(rewritten) = self.rewritten.get(oid) {
            return Ok(rewritten.clone());
        }
        if !self.commit_ids.contains(oid) {
            return Ok(oid.to_string());
        }
        if !self.active.insert(oid.to_string()) {
            return Err(SignError::new("commit graph contains a cycle"));
        }

        let raw = run_git(Some(self.repo), &["cat-file", "commit", oid], None)?;
        let parsed = ParsedCommit::parse(&raw)?;
        let mut parents = Vec::with_capacity(parsed.parents.len());
        for parent in &parsed.parents {
            parents.push(self.rewrite(parent)?);
        }
        let unsigned = parsed.unsigned_with_parents(&parents);
        let signature = self.sign_payload(oid, &unsigned)?;
        let signed = insert_signature(&unsigned, &signature)?;
        let new_oid = String::from_utf8(run_git(
            Some(self.repo),
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            Some(&signed),
        )?)
        .map_err(|_| SignError::new("git returned a non-UTF-8 object id"))?
        .trim()
        .to_string();

        self.active.remove(oid);
        self.rewritten.insert(oid.to_string(), new_oid.clone());
        self.signed_count = self.signed_count.saturating_add(1);
        Ok(new_oid)
    }

    fn sign_payload(&self, oid: &str, payload: &[u8]) -> Result<Vec<u8>, SignError> {
        let payload_path = self.workspace.join(format!("commit-{oid}"));
        fs::write(&payload_path, payload).map_err(|error| SignError::new(error.to_string()))?;
        let status = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", "git", "-f"])
            .arg(self.signing_key)
            .arg(&payload_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .map_err(|error| SignError::new(format!("could not run ssh-keygen: {error}")))?;
        if !status.success() {
            return Err(SignError::new("ssh-keygen refused to sign the commit"));
        }
        // ssh-keygen appends `.sig` to the input path.
        let signature_path = PathBuf::from(format!("{}.sig", payload_path.display()));
        fs::read(signature_path).map_err(|error| SignError::new(error.to_string()))
    }
}

struct ParsedCommit {
    headers: Vec<Header>,
    parents: Vec<String>,
    message: Vec<u8>,
}

struct Header {
    name: Vec<u8>,
    block: Vec<u8>,
}

impl ParsedCommit {
    fn parse(raw: &[u8]) -> Result<Self, SignError> {
        let separator = raw
            .windows(2)
            .position(|window| window == b"\n\n")
            .ok_or_else(|| SignError::new("commit object has no header separator"))?;
        let header_bytes = &raw[..separator];
        let mut headers: Vec<Header> = Vec::new();
        for line in header_bytes.split(|byte| *byte == b'\n') {
            if line.starts_with(b" ") {
                let previous = headers
                    .last_mut()
                    .ok_or_else(|| SignError::new("commit starts with a continuation header"))?;
                previous.block.push(b'\n');
                previous.block.extend_from_slice(line);
                continue;
            }
            let name_end = line
                .iter()
                .position(|byte| *byte == b' ')
                .ok_or_else(|| SignError::new("invalid commit header"))?;
            headers.push(Header {
                name: line[..name_end].to_vec(),
                block: line.to_vec(),
            });
        }
        let parents = headers
            .iter()
            .filter(|header| header.name == b"parent")
            .map(|header| ascii_oid(&header.block[b"parent ".len()..]))
            .collect::<Result<Vec<_>, _>>()?;
        if !headers.iter().any(|header| header.name == b"tree") {
            return Err(SignError::new("commit object has no tree"));
        }
        Ok(Self {
            headers,
            parents,
            message: raw[separator + 2..].to_vec(),
        })
    }

    fn unsigned_with_parents(&self, parents: &[String]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut parent_index = 0;
        for header in &self.headers {
            if header.name == b"gpgsig" || header.name == b"gpgsig-sha256" {
                continue;
            }
            if header.name == b"parent" {
                result.extend_from_slice(b"parent ");
                result.extend_from_slice(parents[parent_index].as_bytes());
                parent_index += 1;
            } else {
                result.extend_from_slice(&header.block);
            }
            result.push(b'\n');
        }
        result.push(b'\n');
        result.extend_from_slice(&self.message);
        result
    }
}

fn insert_signature(unsigned: &[u8], signature: &[u8]) -> Result<Vec<u8>, SignError> {
    let separator = unsigned
        .windows(2)
        .position(|window| window == b"\n\n")
        .ok_or_else(|| SignError::new("unsigned commit has no header separator"))?;
    let signature = signature.strip_suffix(b"\n").unwrap_or(signature);
    let mut result = Vec::with_capacity(unsigned.len() + signature.len() + 16);
    result.extend_from_slice(&unsigned[..separator + 1]);
    for (index, line) in signature.split(|byte| *byte == b'\n').enumerate() {
        result.extend_from_slice(if index == 0 { b"gpgsig " } else { b" " });
        result.extend_from_slice(line);
        result.push(b'\n');
    }
    result.extend_from_slice(&unsigned[separator + 1..]);
    Ok(result)
}

fn repo_string(path: &Path) -> Result<&str, SignError> {
    path.to_str()
        .ok_or_else(|| SignError::new("temporary repository path is not UTF-8"))
}

fn run_git(repo: Option<&Path>, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, SignError> {
    let mut command = Command::new("git");
    if let Some(repo) = repo {
        command.arg("-C").arg(repo);
    }
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| SignError::new(format!("could not run git: {error}")))?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| SignError::new("git stdin was unavailable"))?
            .write_all(input)
            .map_err(|error| SignError::new(error.to_string()))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| SignError::new(error.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SignError::new(format!(
            "git {} failed: {}",
            args.first().copied().unwrap_or("command"),
            stderr.trim()
        )));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_every_commit_and_rewrites_the_branch_tip() {
        let fixture = TempDir::new().unwrap();
        let source = fixture.path().join("source.git");
        run_git(
            None,
            &["init", "--bare", repo_string(&source).unwrap()],
            None,
        )
        .unwrap();
        let blob = object(&source, "blob", b"hello\n");
        let tree_line = format!("100644 blob {blob}\tREADME.md\n");
        let tree = String::from_utf8(
            run_git(Some(&source), &["mktree"], Some(tree_line.as_bytes())).unwrap(),
        )
        .unwrap()
        .trim()
        .to_string();
        let first = unsigned_commit(&source, &tree, None, "first");
        let second = unsigned_commit(&source, &tree, Some(&first), "second");
        let objects = format!("{blob}\n{tree}\n{first}\n{second}\n");
        let pack = run_git(
            Some(&source),
            &["pack-objects", "--stdout"],
            Some(objects.as_bytes()),
        )
        .unwrap();
        let body = receive_pack_body(&second, &pack);

        let key = fixture.path().join("signing-key");
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(status.success());
        let signed = GitSigner::new(key.clone())
            .unwrap()
            .sign_receive_pack(&body, None)
            .unwrap();
        assert_eq!(signed.signed_commits, 2);

        let parsed = ReceivePackRequest::parse(&signed.body).unwrap();
        let new_tip = parsed.updates[0].new_oid.clone();
        assert_ne!(new_tip, second);
        let verify = fixture.path().join("verify.git");
        run_git(
            None,
            &["init", "--bare", repo_string(&verify).unwrap()],
            None,
        )
        .unwrap();
        run_git(
            None,
            &[
                "receive-pack",
                "--stateless-rpc",
                repo_string(&verify).unwrap(),
            ],
            Some(&signed.body),
        )
        .unwrap();
        let received_tip = String::from_utf8(
            run_git(Some(&verify), &["rev-parse", "refs/heads/main"], None).unwrap(),
        )
        .unwrap();
        assert_eq!(received_tip.trim(), new_tip);
        let tip = run_git(Some(&verify), &["cat-file", "commit", &new_tip], None).unwrap();
        assert!(tip.windows(7).any(|window| window == b"gpgsig "));
        let tip = ParsedCommit::parse(&tip).unwrap();
        assert_eq!(tip.parents.len(), 1);
        assert_ne!(tip.parents[0], first);
        let parent = run_git(
            Some(&verify),
            &["cat-file", "commit", &tip.parents[0]],
            None,
        )
        .unwrap();
        assert!(parent.windows(7).any(|window| window == b"gpgsig "));

        let allowed = fixture.path().join("allowed-signers");
        let public_key = fs::read_to_string(key.with_extension("pub")).unwrap();
        fs::write(&allowed, format!("agent@example.com {}", public_key.trim())).unwrap();
        verify_commit(&verify, &allowed, &new_tip);
        verify_commit(&verify, &allowed, &tip.parents[0]);
    }

    #[test]
    fn rejects_non_branch_updates() {
        let payload = format!("{ZERO_SHA1} {ZERO_SHA1} refs/tags/v1\n");
        let length = payload.len() + 4;
        let mut body = format!("{length:04x}{payload}0000").into_bytes();
        body.extend_from_slice(b"PACK");
        let parsed = ReceivePackRequest::parse(&body).unwrap();
        assert_eq!(parsed.updates[0].ref_name, "refs/tags/v1");
    }

    #[test]
    fn resolves_a_thin_pack_from_the_upstream_repository() {
        let fixture = TempDir::new().unwrap();
        let source = fixture.path().join("source.git");
        run_git(
            None,
            &["init", "--bare", repo_string(&source).unwrap()],
            None,
        )
        .unwrap();
        let blob = object(&source, "blob", b"base\n");
        let tree_line = format!("100644 blob {blob}\tREADME.md\n");
        let tree = String::from_utf8(
            run_git(Some(&source), &["mktree"], Some(tree_line.as_bytes())).unwrap(),
        )
        .unwrap()
        .trim()
        .to_string();
        let base = unsigned_commit(&source, &tree, None, "base");
        run_git(
            Some(&source),
            &["update-ref", "refs/heads/main", &base],
            None,
        )
        .unwrap();
        run_git(
            Some(&source),
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            None,
        )
        .unwrap();
        let tip = unsigned_commit(&source, &tree, Some(&base), "tip");
        let revisions = format!("{tip}\n^{base}\n");
        let pack = run_git(
            Some(&source),
            &["pack-objects", "--stdout", "--revs", "--thin"],
            Some(revisions.as_bytes()),
        )
        .unwrap();
        let body = receive_pack_body(&tip, &pack);

        let key = fixture.path().join("signing-key");
        assert!(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .status()
                .unwrap()
                .success()
        );
        let signed = GitSigner::new(key)
            .unwrap()
            .sign_receive_pack(&body, source.to_str())
            .unwrap();
        assert_eq!(signed.signed_commits, 1);
    }

    fn object(repo: &Path, kind: &str, body: &[u8]) -> String {
        String::from_utf8(
            run_git(
                Some(repo),
                &["hash-object", "-t", kind, "-w", "--stdin"],
                Some(body),
            )
            .unwrap(),
        )
        .unwrap()
        .trim()
        .to_string()
    }

    fn unsigned_commit(repo: &Path, tree: &str, parent: Option<&str>, subject: &str) -> String {
        let parent = parent.map_or(String::new(), |oid| format!("parent {oid}\n"));
        let raw = format!(
            "tree {tree}\n{parent}author Agent <agent@example.com> 1700000000 +0000\ncommitter Agent <agent@example.com> 1700000000 +0000\n\n{subject}\n"
        );
        object(repo, "commit", raw.as_bytes())
    }

    fn receive_pack_body(new_oid: &str, pack: &[u8]) -> Vec<u8> {
        let payload = format!(
            "{ZERO_SHA1} {new_oid} refs/heads/main\0 report-status side-band-64k object-format=sha1\n"
        );
        let length = payload.len() + 4;
        let mut body = format!("{length:04x}{payload}0000").into_bytes();
        body.extend_from_slice(pack);
        body
    }

    fn verify_commit(repo: &Path, allowed: &Path, oid: &str) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["-c", "gpg.format=ssh", "-c"])
            .arg(format!("gpg.ssh.allowedSignersFile={}", allowed.display()))
            .args(["verify-commit", oid])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
