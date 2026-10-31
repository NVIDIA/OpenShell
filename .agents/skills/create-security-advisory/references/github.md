# GitHub draft creation

Read this when creating an authorized private GitHub advisory. Formatting a
report alone does not require GitHub write access. Keep the prepared files in
the private directory from the skill and authenticate through `gh`; never put
tokens in the payload or command line.

GitHub's [creation API](https://docs.github.com/en/rest/security-advisories/repository-advisories#create-a-repository-security-advisory)
requires an administrator or security manager with advisory write access.
Check the current [field guidance](https://docs.github.com/en/code-security/tutorials/fix-reported-vulnerabilities/write-security-advisories)
when package identity or version syntax is uncertain. Lack of access means
returning the prepared report for the authorized maintainer, not creating a
public issue.

## Prepare the payload

Set `advisory_repo` to the verified `OWNER/REPO` and `advisory_dir` to the private
directory containing `advisory.md`. Write `metadata.json` with:

- `summary`: the report title.
- `vulnerabilities`: affected package entries, each with `package.ecosystem`
  and the actual `package.name`. Use the distribution ecosystem; a Rust source
  file alone does not establish that a published Rust crate is the affected product.
  `other` is available for products outside a supported package ecosystem.
- `vulnerable_version_range` and `patched_versions` inside each entry: evidence-backed
  release information, or `null` when unknown. Keep commit SHAs and branch names
  in the description, not version-range fields.
- Either `severity` or `cvss_vector_string`, not both. A provisional severity
  needs a rationale in the report; use `null` when undetermined.
- Optional supported `cwe_ids`, existing `cve_id`, and requested `credits`.

Keep unknown optional values null or omitted. Never send template prompts,
invent affected ranges, or populate a patched version from an unmerged fix.
Build the request from the files so Markdown newlines and quotes survive:

```shell
jq --rawfile description "$advisory_dir/advisory.md" \
  '.description = $description | .start_private_fork = false' \
  "$advisory_dir/metadata.json" > "$advisory_dir/request.json"
```

Inspect the complete request before creation. An explicit request to create
this advisory supplies authorization; ask only if the target or permission to
create it remains unclear after the local draft is ready. An explicit draft-only
or no-post instruction means stop with the local artifacts.

## Create and read back

```shell
gh api --method POST "repos/$advisory_repo/security-advisories" \
  -H 'Accept: application/vnd.github+json' \
  --input "$advisory_dir/request.json" > "$advisory_dir/created.json"
```

The creation endpoint creates a private draft. Do not call the publication,
CVE-request, or private-fork endpoints. If the POST times out or its outcome is
ambiguous, inspect existing advisories before retrying; never blindly repeat
creation. A validation error calls for fixing the reported field, not guessing
missing facts or repeatedly resubmitting.

After a successful creation:

```shell
advisory_id=$(jq -er '.ghsa_id' "$advisory_dir/created.json")
gh api --method GET "repos/$advisory_repo/security-advisories/$advisory_id" \
  > "$advisory_dir/verified.json"
jq '{ghsa_id, html_url, state, summary}' "$advisory_dir/verified.json"
```

Verify `state` is `draft`, no private fork was created, and the description and
affected-product metadata match the prepared request. Report the private URL
and remaining evidence gaps. An unexpected state or failed read-back must be
reported as such, not described as a successfully verified draft.
