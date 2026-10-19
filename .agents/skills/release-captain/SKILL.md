---
name: release-captain
description: Run the weekly OpenShell release captain checklist. Monday checks that the current pre-release train is qualified, triages qualification, compatibility, and security reports, and prepares the release coordination post. Tuesday selects the final qualified pre-release, tags its commit as stable after maintainer approval, verifies publication, and starts the next train. Trigger keywords - release captain, weekly release, Tuesday release, cut the release, release checklist, pre-release status, release train, start next train, stable release.
metadata:
  internal: true
---

# Release Captain

OpenShell publishes a stable release every Tuesday from a qualified
pre-release ([RFC 0014](../../../rfc/0014-release-stability/README.md)). The
release captain keeps the week's pre-release train green, coordinates the last
merges, and cuts the release. `CI.md` describes the release workflows,
qualification profile, and scanner policies. This skill covers what the captain
does with them.

## Guardrails

Without explicit approval from the release captain or a maintainer for that
specific action, never:

- push, move, or delete a tag;
- dispatch, cancel, or rerun any workflow;
- merge, approve, or enqueue a PR;
- post in Slack or comment on GitHub;
- install OpenShell or change the local machine.

Ask for approval with the exact command and target commit SHA. Every other
step in this skill is read-only.

Never repoint a stable tag at a different commit, and never re-dispatch a
release while an earlier run for the same tag might still start. `Release Tag`
has no concurrency guard, so two runs race to publish. Don't delete `-pre.N`
tags; the RFC's cleanup step is not implemented and tag deletion is restricted.

## How the train works

- A train has one base version, such as `v0.1.4`, fixed by its `-pre.1` tag. A
  patch train can't take breaking changes to Stable interfaces. Those wait for a
  minor train.
- `Release Auto-Tag` runs Monday through Friday at 14:00 Europe/Zurich. That's
  12:00 UTC during Central European Summer Time and 13:00 UTC in winter. If
  `main` has commits since the latest `-pre.N`, it tags the next one and
  dispatches `Release Tag` (about 45 minutes). It skips after the base version
  gets a stable tag, and fails if the latest pre-release isn't an ancestor of
  `main`. A skip still counts as a successful run.
- Pushing any release tag by hand, pre-release or stable, starts `Release Tag`.
  Don't also dispatch it, or two runs race to publish. Auto-Tag dispatches
  explicitly only because its `GITHUB_TOKEN` push can't trigger workflows.
- A stable `vX.Y.Z` tag push rebuilds and requalifies the commit. Always tag
  the commit of a pre-release that passed.
- Codex Security is temporarily excluded from release qualification (#4469).
  `CI.md` explains how to run it by hand against a `-pre.N` candidate.
- Only stable tags create a GitHub Release, so pre-releases never appear on the
  Releases page. A passing pre-release publishes its images, Helm chart, and
  qualification summary to GHCR. Its Debian, RPM, and macOS packages stay as
  artifacts on the `Release Tag` run. To check a pre-release, look at the tag
  and that run.
- OpenShell TriageBot posts a top-level message in `#openshell-triage`
  (`C0C20SDLDNW`) for every failed `Release Tag` attempt, with a link to the
  run. Each rerun that fails gets its own message.

## Setup

Run from an OpenShell checkout with an authenticated `gh` CLI. Fetch tags with
`--force`, because release tags have been removed and recreated, and a plain
fetch keeps stale local copies:

```shell
export GH_REPO=NVIDIA/OpenShell
git fetch origin main --tags --force
PREV=$(git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
echo "Latest stable: $PREV"
git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+-pre\.[0-9]+$' | head -5
```

Release workflows change often, and a local branch may be days behind. Before
relying on trigger or job behavior, including anything in this skill, read the
current workflow from `origin/main`:

```shell
git show origin/main:.github/workflows/release-tag.yml | sed -n '/^on:/,/^permissions:/p'
```

Release tags are lightweight, matching the tags Auto-Tag creates. The tag
commands below pass `-c tag.gpgSign=false` and read from `/dev/null`. With
`tag.gpgSign` set, `git tag` would otherwise create a signed annotated tag and
wait in an editor for a message.

Find the `Release Tag` run for a tag. A tag pushed by hand runs on the tag
itself. An Auto-Tag run is dispatched on `main`, so its head commit is the
tagged commit:

```shell
TAG=vX.Y.Z-pre.N
gh run list --workflow release-tag.yml --branch "$TAG"
gh run list --workflow release-tag.yml --event workflow_dispatch --commit "$(git rev-parse "$TAG^{commit}")"
```

If a commit has several dispatched runs, the one with a
`qualification-$TAG-run-*` artifact is the match. That artifact appears only
after qualification finishes:

```shell
gh api "repos/NVIDIA/OpenShell/actions/runs/<run-id>/artifacts?per_page=100" --jq '.artifacts[].name' | grep "qualification-$TAG-"
```

## Monday: pre-flight

Finish these on Monday so Tuesday is only the cut.

1. **Check the train.** Confirm that the latest `-pre.N` targets the version you
   plan to ship. Check that today's `Release Auto-Tag` run (14:00
   Europe/Zurich) succeeded, and check from its log whether it tagged or
   skipped:

   ```shell
   gh run list --workflow release-auto-tag.yml --limit 3
   gh run view "$(gh run list --workflow release-auto-tag.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --log | grep -E 'Next tag:|— skipping' | grep -v echo
   ```

   If the next version has no `-pre.1`, start the train (Tuesday step 6).

2. **Read the qualification summary for the latest attempt.** The summary's
   `tag` and `source_sha` must match the candidate, and `current_profile_passed`
   must be `true`:

   ```shell
   RUN=<run-id>
   ATTEMPT=$(gh run view "$RUN" --json attempt --jq .attempt)
   dir=$(mktemp -d)
   gh run download "$RUN" -n "qualification-$TAG-run-$RUN-attempt-$ATTEMPT" -D "$dir/q"
   jq '{tag, source_sha, current_profile_passed, suites}' "$dir/q/qualification-summary.json"
   git rev-parse "$TAG^{commit}"
   ```

   For any failed suite, read the log with `gh run view "$RUN" --log-failed`.
   `CI.md` lists which scanners block. Use the `watch-github-actions` skill for
   CI diagnosis.

3. **Triage the advisory compatibility review.** It never blocks publication,
   and a green job doesn't mean it found no breaks:

   ```shell
   gh run download "$RUN" -n "compatibility-review-run-$RUN-attempt-$ATTEMPT" -D "$dir/c"
   jq '{status, verdict: .review.verdict}' "$dir/c/report.json"
   cat "$dir/c/report.md"
   ```

   Only `complete` with `no_unaddressed_breaks` is a clean review. A missing
   report or any other result means there's no assessment. For each finding,
   decide whether it's a real break, a false positive, or unclear:

   - **Real break:** needs a fix or revert before Tuesday, or must wait for a
     minor train.
   - **Unclear:** ask an owner of that code.
   - **False positive:** send it to the owner of
     `.github/prompts/compatibility-review.md` so the prompt can be tuned.

   The reviewer treats every `pub` Rust item as a Stable interface. No
   workspace crate is published to crates.io, so a finding in an internal
   crate such as `openshell-core` or `openshell-isolation-interface` is often a
   false positive. Check whether a supported SDK surface, such as
   `openshell-sdk`, exposes the item before deciding.

4. **Check the dev canary.** `Release Canary` smoke-tests `main` dev artifacts.
   It doesn't gate the tag, but treat a red canary as a release risk. Use the
   `test-release-canary` skill to diagnose it:

   ```shell
   gh run list --workflow release-canary.yml --limit 3
   ```

5. **Plan fixes.** A failed pre-release doesn't end the train. The goal is a
   green pre-release before Tuesday, so fix forward:

   - Reply in the thread of the failure's `#openshell-triage` message, so
     others know someone is working on a fix. Post the cause and the fix or
     rerun, then post again when a pre-release passes. Draft these replies for
     the captain to post.
   - A transient infrastructure failure can be rerun after approval. Runner
     setup errors, registry push errors, and integration tests that fail only
     some of the time are common. If a failure looks unrelated to the commit's
     changes, rerun once before treating it as a code defect.
   - A code defect, or a new advisory against a locked dependency, needs a
     merged fix and a new pre-release. Don't rerun or promote the failed one.
   - Let the failed run finish rather than cancelling it. Its other suites
     still show whether the rest of the commit is healthy.
   - Once the fix merges and its `Release Dev` run passes, tag the next
     `-pre.N` on that commit by hand after approval (as in Tuesday step 6, with
     the next number), instead of waiting for the next Auto-Tag run. That
     gives a qualifiable candidate a day sooner.

6. **Draft the coordination post.** Release coordination happens in a thread
   the captain starts on Monday in the OpenShell channel of the CNCF Slack
   (`cloud-native.slack.com`, channel `C0B6Y8WQHU1`). Also link the thread in
   the internal team channel. The thread asks contributors to link ready PRs
   they want in the release. The release ships from `main`; there's no release
   branch and no cherry-picking. The list exists so the captain can get those
   PRs reviewed and merged in order before the cutoff. Tag reviewers on the
   linked PRs. Draft it for the captain to post:

   - the target version and current candidate (tag, commit, run link);
   - qualification and compatibility status, with an owner for each blocker;
   - ready but unmerged PRs that should make the release, in merge order;
   - the merge cutoff in UTC and the captain's time zone. Set it before
     Tuesday's 14:00 Europe/Zurich Auto-Tag run so the last merges make that
     pre-release.

   Candidate PRs:

   ```shell
   gh pr list --base main --state open --search "review:approved" --json number,title,author --jq '.[] | "#\(.number) \(.title) (@\(.author.login))"'
   ```

   Example post:

   ```text
   :thread: OpenShell vX.Y.Z release, Tuesday <date>. I'm release captain this week.

   Status: vX.Y.Z-pre.N (<commit>) passed qualification. <blockers and owners, or "No blockers.">

   Reply here with any ready PRs you'd like in vX.Y.Z. Merge cutoff is <HH:MM UTC> (<captain's local time>) Tuesday, before the next pre-release is cut. Anything merged on main by then ships; anything later goes in the next release.
   ```

## Tuesday: cut the release

1. **Select the final candidate.** After the cutoff and Tuesday's Auto-Tag run,
   pick the newest `-pre.N` whose qualification passed, and repeat Monday steps
   2 and 3 for it. If the newest pre-release failed, either merge a fix and
   qualify another pre-release, or pick an earlier one that passed and confirm
   that leaving out the later commits is acceptable.

2. **Request approval.** Present the candidate tag, commit SHA, qualification
   run, compatibility assessment, and the commits since `$PREV`:

   ```shell
   git log --oneline --no-merges "$PREV..$TAG"
   ```

3. **Tag the stable release.** After approval, check the candidate, then tag its
   exact commit and push only that tag:

   ```shell
   VERSION=vX.Y.Z
   SHA=$(git rev-parse "$TAG^{commit}")
   [[ "$VERSION" == "${TAG%-pre.*}" ]] || echo "version does not match the train"
   [[ "$SHA" == "$(jq -r .source_sha "$dir/q/qualification-summary.json")" ]] || echo "commit does not match qualification"
   git tag --points-at "$SHA" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' && echo "commit already has a stable tag"
   git -c tag.gpgSign=false tag "$VERSION" "$SHA" </dev/null
   git push origin "refs/tags/$VERSION"
   ```

   Stop if any check prints a message.

4. **Watch the release.** The tag push starts `Release Tag`. It runs for about
   45 minutes, so poll the status, or run the watch in the background:

   ```shell
   gh run list --workflow release-tag.yml --branch "$VERSION" --limit 1
   gh run watch <run-id> --exit-status
   ```

   If no run appears within a few minutes, or the run stays queued, see
   Recovery.

5. **Verify publication.** Confirm that the GitHub Release exists as a
   non-pre-release with assets and generated notes, and that no job failed:

   ```shell
   gh release view "$VERSION" --json name,isPrerelease,publishedAt,assets --jq '{name, isPrerelease, publishedAt, assets: (.assets | length)}'
   gh run view <run-id> --json jobs --jq '.jobs[] | select(.conclusion != "success" and .conclusion != "skipped") | "\(.conclusion)\t\(.name)"'
   ```

   `Trigger Wheel Publish` only starts the GitLab pipeline, so confirm that the
   Python wheel reached PyPI separately.

6. **Start the next train.** Until someone pushes the next `-pre.1`, Auto-Tag
   logs `vX.Y.Z is already stable — skipping tag creation` and does nothing.
   Starting it is this week's captain's job, not next week's: once `-pre.1`
   exists, Auto-Tag cuts `-pre.2` onward every weekday, so next week's captain
   starts Monday with pre-releases already qualifying. Start the train soon
   after the stable release; it can be any weekday.

   Agree with the maintainers whether the next train is patch (the default) or
   minor (notable features or planned breaking changes; see the
   [version selection supplement](../../../rfc/0014-release-stability/release-version-selection.md)).
   List the commit types since the release to inform the decision:

   ```shell
   git log --format=%s --no-merges "$VERSION..origin/main" | sed -E 's/^([a-z]+)(\(.*\))?(!?):.*/\1\3/' | sort | uniq -c
   ```

   Seed the train on a `main` commit that:

   - comes after `$VERSION`;
   - has no stable tag of its own;
   - has a successful `Release Dev` run.

   Release versioning prefers a stable tag over a pre-release tag on the same
   commit, which would mislabel the packages. If nothing has merged since the
   release, wait.

   Branch Checks already passed in the merge queue before each merge.
   `Release Dev` runs the post-merge E2E and dev publication on every commit. A
   newer push cancels the older run, so `cancelled` means superseded, not
   failed. Pick the newest commit whose run succeeded, or wait for the tip's
   run to finish:

   ```shell
   for sha in $(git rev-list --max-count=10 "$VERSION..origin/main"); do
     state=$(gh run list --workflow release-dev.yml --commit "$sha" --json status,conclusion --jq '.[0] | if .status == "completed" then .conclusion else .status end')
     echo "${sha:0:9} ${state:-none} $(git log -1 --format=%s "$sha")"
   done
   ```

   After approval, push the tag. The push starts `Release Tag`; don't dispatch
   it as well:

   ```shell
   NEXT=vX.Y.Z-pre.1
   NEXT_SHA=<main commit>
   git merge-base --is-ancestor "$VERSION" "$NEXT_SHA" || echo "commit does not contain the release"
   git tag --points-at "$NEXT_SHA" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' && echo "commit already has a stable tag"
   git -c tag.gpgSign=false tag "$NEXT" "$NEXT_SHA" </dev/null
   git push origin "refs/tags/$NEXT"
   gh run list --workflow release-tag.yml --branch "$NEXT"
   ```

   Stop if either check prints a message. The rolling `dev` tag may point at
   the same commit; it isn't a release tag and doesn't affect versioning.

   The run should appear as `queued` within a minute. Watch it as in Tuesday
   step 4, then read its qualification summary (Monday step 2). It won't appear
   on the Releases page. From the next weekday, Auto-Tag creates `-pre.2` onward
   when `main` has new commits.

7. **Close the loop.** Draft a reply to the coordination thread with the release
   link and any PRs deferred to the next train.

## Recovery

| Symptom | Action |
|---|---|
| Transient infrastructure failure in a pre-release | After approval, run `gh run rerun <run-id> --failed`, then recheck the new attempt's summary. Reply in the failure's `#openshell-triage` thread with the result. |
| Code defect in a pre-release | Fix forward (Monday step 5): merge the fix, then, after approval, tag and push the next `-pre.N` on the fix commit once its `Release Dev` run passes. Waiting for Auto-Tag also works but costs up to a day. |
| `Cargo Deny` fails a pre-release with `error[vulnerability]` | A new RustSec advisory was published against a locked dependency. Code that passed earlier can start failing this way. Rerunning won't help. Find the advisory IDs with `gh run view <run-id> --log-failed \| grep -E 'ID: RUSTSEC'`, look for an open dependency bump PR, and treat the merged bump as a code-defect fix. |
| A pushed tag started no `Release Tag` run | Wait a few minutes and check `gh run list --workflow release-tag.yml --branch "$TAG"` again. Only after confirming that no run exists, and with approval, dispatch it with `gh workflow run release-tag.yml --ref main -f tag="$TAG"`. |
| Stable run stuck queued | Don't re-dispatch or delete the tag. Check for a GitHub Actions incident and ask a maintainer to cancel the run (`gh run cancel <run-id>`, or force-cancel through the API). Only after it shows `cancelled` or `failed`, rerun it after approval. |
| Stable run fails before the `Release` job, transient | Nothing was published. After approval, run `gh run rerun <run-id> --failed`. |
| Stable run fails before the `Release` job, code defect | Nothing was published, and Auto-Tag won't create pre-releases for a base version that has a stable tag. Ask the maintainers to choose: remove the unpublished tag (needs a ruleset bypass) and recut from a qualified fix, or skip to the next patch version. |
| Stable run fails after the `Release` job | The GitHub Release exists. Check which publish jobs succeeded. A rerun of an npm or snap publish fails if that version already went out. Rerun only jobs that didn't publish, after approval. |

## Related

- `release-openshell`: the short procedure for selecting a qualified
  pre-release and tagging it stable.
- `watch-github-actions`: general `gh run` monitoring and log retrieval.
- `test-release-canary`: diagnose dev artifact smoke-test failures.
- `CI.md`: release workflows, qualification profile, and scanner policies.
- `rfc/0014-release-stability/`: cadence, qualification, and version selection.
