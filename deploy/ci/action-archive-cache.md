# Runner action archive cache proposal

This proposal mitigates the Debian action preparation failure tracked in [#4085](https://github.com/NVIDIA/OpenShell/issues/4085). It requires NVIDIA runner administrators to provision a cache and configure the runner process. OpenShell workflows do not activate it. Fleet support, rollout, and fault-injection validation remain unverified.

## Observed failure

[Job 110603806594](https://github.com/NVIDIA/OpenShell/actions/runs/36931039020/job/110603806594) failed on October 1, 2026 at 21:58:38 UTC during `Prepare all required actions`, before checkout or packaging steps. The candidate SHA was `76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2`. The runner reported version 2.337.0, NVIDIA runtime v1.9.0, and VM image 24b0d8a.

```text
An action could not be found at the URI 'https://codeload.github.com/actions/download-artifact/tar.gz/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c' (D816:182C54:1541E2:1BDDEE:6ABED78E)
Failed to download archive 'https://codeload.github.com/actions/download-artifact/tar.gz/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c' after 1 attempts.
```

The [pinned commit exists](https://github.com/actions/download-artifact/commit/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c). [Earlier amd64 Debian packaging](https://github.com/NVIDIA/OpenShell/actions/runs/36914303849/job/110548990503) downloaded that same pin and succeeded with the same runner version and image. Its arm64 sibling also succeeded. The archive downloaded successfully during investigation. These observations support a transient failure but do not establish the cause of the original 404 or its repeatability.

The failed job canceled its arm64 sibling and skipped package-dependent integration, including K3s conformance. Those results do not establish additional flakes. Preserve attempt 1's log, job metadata, SHA, runner/image versions, timestamps, and request ID before any rerun; report subsequent attempts separately.

## Why workflow retries cannot fix it

In [runner 2.337.0's archive downloader](https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/ActionManager.cs#L1644-L1770), HTTP 404 throws `ActionNotFoundException` and exits immediately; HTTP 403 also exits immediately. Other download failures already receive up to three attempts, with 10–30 second backoff or the bounded `Retry-After` delay for throttling. No configurable 404 retry count exists in this code. `_GITHUB_ACTION_DOWNLOAD_NO_BACKOFF` removes delays; it does not enable 404 retries. Upstream main at `539695a10a5b0fe3af98990525044236bfa67a75` retains this behavior.

The runner prepares remote actions before executing workflow steps. Retrying a packaging command, wrapping the action body, setting `continue-on-error`, or adding a later setup step cannot catch this exception. Changing the action pin is unsupported by the evidence. Broad job reruns can conceal unrelated failures and rebuild already-successful work.

## Proposed fleet configuration

Use the runner's existing archive cache for this exact public action pin. [Constants.cs](https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Common/Constants.cs#L327-L328) defines `ACTIONS_RUNNER_ACTION_ARCHIVE_CACHE`; [ActionManager.cs](https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/ActionManager.cs#L1230-L1306) reads it from the worker process environment, copies a matching archive, and bypasses the archive HTTP request. Action download-info resolution still requires GitHub connectivity.

Runner administrators should bake the archive into both Linux runner images, using a trusted image-build process and the unchanged codeload URL. Populate the cache before any job is accepted. For example, run this Bash recipe in the image build after creating an administrator-owned `/opt/actions-archive-cache` directory. It requires [curl 7.71.0 or newer](https://curl.se/docs/manpage.html#--retry-all-errors):

```shell
set -euo pipefail
action_sha=3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
cache_dir=/opt/actions-archive-cache/actions_download-artifact
mkdir -p "$cache_dir"
stage_dir=$(mktemp -d "$cache_dir/.populate.XXXXXX")
trap 'rm -rf "$stage_dir"' EXIT
curl --fail --show-error --location \
  --retry 2 --retry-all-errors --retry-delay 10 \
  --connect-timeout 10 --max-time 60 --retry-max-time 200 \
  --output "$stage_dir/action.tar.gz" \
  "https://codeload.github.com/actions/download-artifact/tar.gz/$action_sha"
tar -tzf "$stage_dir/action.tar.gz" > "$stage_dir/members"
grep -Fxq "download-artifact-$action_sha/action.yml" "$stage_dir/members"
grep -Fxq "download-artifact-$action_sha/dist/index.js" "$stage_dir/members"
chmod 0444 "$stage_dir/action.tar.gz"
mv "$stage_dir/action.tar.gz" "$cache_dir/$action_sha.tar.gz"
```

This makes at most three transfer attempts, including 404s during provisioning, with a 60-second timeout per attempt and 10-second retry delays unless a server supplies `Retry-After`. The [200-second retry budget](https://curl.se/docs/manpage.html#--retry-max-time) limits starting retries; it is not a hard deadline for an already-started transfer. A permanent HTTP error fails the image build after the bounded attempts. Invalid or incomplete archives fail validation before publication. Curl emits the first failure and retry diagnostics to stderr; retain the complete image-build log even when a later attempt succeeds. The final archive is published by a same-directory rename only after validation. The layout and member checks verify structure; they are not independent proof of source authenticity.

Retain the source URL, pin, download date, and archive SHA-256 in the trusted image-build provenance. GitHub-generated archive bytes may change, so a newly observed digest needs trusted review rather than assuming the commit SHA is a content digest. Ensure the cache and its parent directories are administrator-owned and cannot be replaced or modified by workflow users. Mount it read-only to the worker when applicable. Do not populate a shared cache from repository-controlled job steps.

Configure the runner service/container environment before it starts:

```text
ACTIONS_RUNNER_ACTION_ARCHIVE_CACHE=/opt/actions-archive-cache
```

Keep `ACTIONS_RUNNER_SYMLINK_CACHED_ACTIONS` unset so the archive-copy path is used. A workflow `env:` entry or `GITHUB_ENV` write does not configure this worker process setting: [job environment evaluation](https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/JobExtension.cs#L235-L245) stores step environment values separately. This cache mitigates the selected archive-fetch boundary; it does not add 404 retries to the runner. Missing/unreadable entries fall back to the existing HTTP behavior. Other remote actions and action resolution remain exposed to download failures.

## Required infrastructure validation

1. Confirm the managed fleet supports the process environment setting and administrator-owned cache on both `linux-amd64-cpu8` and `linux-arm64-cpu8`. The runner support site requires NVIDIA SSO; this investigation could not inspect fleet configuration.
2. Test population with controlled HTTP sequences: 404 then valid archive succeeds on attempt two; three 404s fail with no published archive; an invalid archive fails without publication. Verify the three-attempt ceiling, first-failure log retention, cleanup, and time limits. Keep fault injection outside production jobs.
3. In a disposable runner matching 2.337.0, supply the cache and make this action's codeload URL return 404 while preserving action resolution. Verify the worker log reports the cache copy and the job proceeds without requesting that archive. Ordinary green packaging does not prove this path was exercised.
4. Repeat with a cache miss, an unreadable cache, and a corrupt archive. A miss/unreadable entry must retain the original failing behavior; corrupt data must fail extraction. Confirm a permanently unavailable uncached action still fails and no packaging failure is converted into success.
5. Run Branch E2E on the candidate PR SHA with matching binaries/images/packages. Verify both Debian architectures and the dependent Ubuntu Docker and K3s conformance lanes. Record cache usage separately from baseline CI results and retain the original failed attempt.

Apply only after runner-admin review. To roll back, remove the process environment setting and retire the cache image through the fleet's normal image rollout. No repository workflow changes are needed. If the fleet cannot support this cache, a runner-side change to bound retries for an already-resolved action's 404 requires a separate upstream/fleet patch and cancellation/permanent-failure tests; there is no verified configuration switch for it.
