---
name: release-captain
description: Run the weekly OpenShell release captain checklist. Monday checks that the current pre-release train is qualified, triages qualification, compatibility, and security reports, and prepares the release coordination post. Tuesday previews the qualified pre-release that Release will promote, dispatches Release after maintainer approval, verifies publication, and starts the next train. Trigger keywords - release captain, weekly release, Tuesday release, cut the release, release checklist, pre-release status, release train, start next train, stable release.
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

## How to use this skill

Ask for the part of the week you're in:

| When | Ask | What happens |
|---|---|---|
| The week before your turn | "I'm release captain next week. Is the train ready?" | Checks that the next version's `-pre.1` exists and Auto-Tag is cutting pre-releases. If not, ask this week's captain to start the train (Tuesday step 7). Nothing else is needed until Monday. |
| Monday | "Run the release captain Monday checklist." | Monday steps 1–6: candidate status, failure triage, compatibility review, canary, and a draft coordination post. |
| A pre-release failed | "`vX.Y.Z-pre.N` failed, help me fix it." | Monday step 5 and Recovery: classify the failure, propose a rerun or fix, and draft the `#openshell-triage` reply. |
| Tuesday | "Cut the release." | Tuesday steps 1–7: preview the candidate, dispatch `Release` after approval, verify, close the loop, and finish by starting the next train. |

Every command that changes something is shown for approval first.

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

Never repoint a stable tag, and don't delete `-pre.N` tags; tag deletion is
restricted. `Pre-release` has no concurrency guard, so never start a second run
for a tag while an earlier one might still start.

## How the train works

- A train has one base version, such as `v0.1.4`, fixed by its `-pre.1` tag. A
  patch train can't take breaking changes to Stable interfaces. Those wait for a
  minor train.
- `Release Auto-Tag` runs Monday through Friday at 14:00 Europe/Zurich (12:00
  UTC in summer, 13:00 UTC in winter). If `main` has commits since the latest
  `-pre.N`, it tags the next one and dispatches `Pre-release`
  (`release-prerelease.yml`, about 45 minutes). It skips when the train has no
  `-pre.1` or the base version is already stable. A skip still counts as a
  successful run.
- `Pre-release` builds, then publishes and qualifies in parallel. Its artifacts
  are published even when qualification fails. Pushing a `-pre.N` tag by hand
  starts it; don't also dispatch it.
- `Release` (`release.yml`) is dispatched by hand with the stable version. It
  picks the highest `-pre.N` on `main` whose whole `Pre-release` run passed,
  creates the stable tag on that commit, then rebuilds and publishes without
  requalifying. Pushing a stable tag does nothing.
- Pre-releases never appear on the Releases page. Their images, Helm chart, and
  qualification summary go to GHCR; packages stay as run artifacts.
- OpenShell TriageBot posts in `#openshell-triage` (`C0C20SDLDNW`) for every
  failed `Pre-release` attempt, with links to the failed jobs.

## Setup

Run from an OpenShell checkout with an authenticated `gh` CLI. Fetch tags with
`--force`, because release tags have been removed and recreated:

```shell
export GH_REPO=NVIDIA/OpenShell
git fetch origin main --tags --force
PREV=$(git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
echo "Latest stable: $PREV"
git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+-pre\.[0-9]+$' | head -5
```

Release workflows change often. Before relying on anything in this skill, check
the release workflows on `origin/main` and their recent history:

```shell
git ls-tree --name-only origin/main .github/workflows/ | grep release
git log --oneline -5 origin/main -- '.github/workflows/release*.yml'
```

Find the `Pre-release` run for a tag. A tag pushed by hand runs on the tag; an
Auto-Tag run is dispatched on `main` at the tagged commit:

```shell
TAG=vX.Y.Z-pre.N
gh run list --workflow release-prerelease.yml --branch "$TAG"
gh run list --workflow release-prerelease.yml --event workflow_dispatch --commit "$(git rev-parse "$TAG^{commit}")"
```

Preview the candidate `Release` would promote. This runs the same selection
script, read-only, from a temporary `origin/main` checkout:

```shell
VERSION=vX.Y.Z
wt=$(mktemp -d)
git worktree add -q --detach "$wt" origin/main
(cd "$wt" && GITHUB_REPOSITORY=NVIDIA/OpenShell uv run -q --no-project python tasks/scripts/select-release-candidate.py "$VERSION" --branch main | jq .)
git worktree remove --force "$wt"
```

## Monday: pre-flight

Finish these on Monday so Tuesday is only the cut.

1. **Check the train.** Confirm that the latest `-pre.N` targets the version you
   plan to ship, and whether today's Auto-Tag run tagged or skipped:

   ```shell
   gh run view "$(gh run list --workflow release-auto-tag.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --log | grep -E 'Next tag:|— skipping' | grep -v echo
   ```

   If the next version has no `-pre.1`, start the train (Tuesday step 7).

2. **Check the candidate.** Run the preview from Setup. It shows the newest
   pre-release that would ship. If the latest `-pre.N` isn't the candidate,
   its run failed; read why:

   ```shell
   RUN=<run-id>
   gh run view "$RUN" --json jobs --jq '.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out") | "\(.name)\t\(.url)"'
   gh run view "$RUN" --log-failed
   ```

   `CI.md` lists which scanners block. Use the `watch-github-actions` skill for
   CI diagnosis.

3. **Triage the advisory compatibility review** for the candidate's run. It
   never blocks publication, and a green job doesn't mean it found no breaks:

   ```shell
   ATTEMPT=$(gh run view "$RUN" --json attempt --jq .attempt)
   dir=$(mktemp -d)
   gh run download "$RUN" -n "compatibility-review-run-$RUN-attempt-$ATTEMPT" -D "$dir"
   jq '{status, verdict: .review.verdict}' "$dir/report.json"
   cat "$dir/report.md"
   ```

   Only `complete` with `no_unaddressed_breaks` is a clean review. Anything
   else means there's no assessment. For each finding:

   - **Real break:** needs a fix or revert before Tuesday, or must wait for a
     minor train. A break whose author accepted the risk on the PR can ship
     in a patch only if the maintainers agree to the exception (as for the
     Go SDK change in v0.1.5). Check that the release notes preview (Tuesday
     step 2) gives upgrade steps for it.
   - **Unclear:** ask an owner of that code.
   - **False positive:** send it to the owner of
     `.github/prompts/compatibility-review.md` so the prompt can be tuned.

   The reviewer treats every `pub` Rust item as a Stable interface. No
   workspace crate is published to crates.io, so a finding in an internal
   crate such as `openshell-core` is often a false positive. Check whether a
   supported SDK surface, such as `openshell-sdk`, exposes the item.

4. **Check the dev canary.** `Release Canary` smoke-tests `main` dev artifacts.
   It doesn't gate the release, but treat a red canary as a risk. Use the
   `test-release-canary` skill to diagnose it:

   ```shell
   gh run list --workflow release-canary.yml --limit 3
   ```

5. **Plan fixes.** A failed pre-release doesn't end the train. Fix forward to a
   green pre-release before Tuesday:

   - Reply in the thread of the failure's `#openshell-triage` message with the
     cause and the fix or rerun, then again when a pre-release passes. Draft
     these replies for the captain to post.
   - Rerun a transient infrastructure failure once, after approval: runner
     setup errors, registry push errors, and intermittent integration tests.
   - A code defect, or a new advisory against a locked dependency, needs a
     merged fix and a new pre-release. Don't rerun the failed one.
   - Let a failed run finish rather than cancelling it. Its other suites still
     show whether the rest of the commit is healthy.
   - Once the fix merges and its `Release Dev` run passes, tag the next
     `-pre.N` on that commit by hand after approval (as in Tuesday step 7),
     instead of waiting a day for Auto-Tag.

6. **Draft the coordination post.** The captain starts a thread on Monday in the
   OpenShell channel of the CNCF Slack (`cloud-native.slack.com`, channel
   `C0B6Y8WQHU1`) and links it in the internal team channel. Contributors reply
   with ready PRs they want in the release. The release ships from `main`, with
   no release branch or cherry-picks, so the list is for getting those PRs
   reviewed and merged before the cutoff. Tag reviewers on the linked PRs.

   The release ships one commit: the final pre-release's, if it passes. A PR
   ships only if that pre-release includes it. If the final pre-release fails
   and can't be fixed in time, `Release` falls back to an earlier passing one,
   and later merges miss the release. Pick one of two cutoffs:

   - **Before Tuesday's Auto-Tag run** (14:00 Europe/Zurich): Auto-Tag tags the
     tip of `main`, so everything merged by the cutoff is in it, along with
     anything merged before the run starts. Suits a captain in Europe.
   - **Later on Tuesday:** after the cutoff, the captain tags the final
     pre-release by hand on a commit they choose, then waits about 45 minutes
     for it to qualify. Suits a captain in the Americas, where the Auto-Tag run
     is before the workday.

   Don't promise that everything merged by the cutoff ships, or name the next
   version; it's a patch by default but may be a minor. Approved open PRs:

   ```shell
   gh pr list --base main --state open --search "review:approved" --json number,title,author --jq '.[] | "#\(.number) \(.title) (@\(.author.login))"'
   ```

   Example post:

   ```text
   :thread: OpenShell vX.Y.Z release, Tuesday <date>. I'm release captain this week.

   Status: vX.Y.Z-pre.N (<commit>) passed qualification. <blockers and owners, or "No blockers.">

   Reply here with any ready PRs you'd like in vX.Y.Z. Merge cutoff is <HH:MM UTC> (<captain's local time>) Tuesday. I'll cut the final pre-release after the cutoff, and vX.Y.Z ships from it if it passes qualification. Anything that misses it goes in the next release.
   ```

   For an Auto-Tag cutoff, replace the second sentence with "Tuesday's
   automatic pre-release picks up everything merged by then, and vX.Y.Z ships
   from it if it passes qualification."

   The posted cutoff must match the pre-release that ships. If you end up
   shipping one cut before the posted cutoff, such as Auto-Tag's or a fix-up
   tagged early, reply in the thread with its commit and time, and say that
   later merges go in the next release. For v0.1.5, the post said 16:00 UTC,
   but `pre.7` was cut at 12:38 UTC.

## Tuesday: cut the release

1. **Select the final candidate.** With a cutoff after Auto-Tag, first tag the
   final `-pre.N` by hand after approval, on the newest commit with a
   successful `Release Dev` run (commands as in Tuesday step 7). Once the final
   pre-release has finished, run the preview from Setup and repeat Monday
   step 3 for its run. If the newest pre-release failed, either fix it (Monday
   step 5) or confirm that shipping the earlier candidate without the later
   commits is acceptable. If qualification passed but publication failed, rerun the
   failed jobs first; `Release` needs the whole run to pass.

2. **Request approval.** Present the candidate tag, commit, qualification run,
   compatibility assessment, release notes preview, and the commits since
   `$PREV`:

   ```shell
   git log --oneline --no-merges "$PREV..<candidate_tag>"
   gh run download "$RUN" -n release-notes -D "$dir/notes" && cat "$dir/notes/release-notes.md"
   ```

   Release notes are generated from the merged PRs, including each PR's
   "Release Notes" section, by `release-notes.yml`. Every `Pre-release` run
   writes an advisory preview as its `release-notes` artifact. `Release`
   writes them again in `Publish / Write Release Notes` and uses them as the
   GitHub Release body, so the final text can differ slightly from the
   preview. Check that upgrade notes cover every accepted break. To fix the
   notes, edit the PR's Release Notes section and preview again without
   publishing:

   ```shell
   gh workflow run release.yml --ref main -f tag="$VERSION" -f notes-only=true
   ```

3. **Dispatch the release.** After approval:

   ```shell
   gh workflow run release.yml --ref main -f tag="$VERSION"
   ```

4. **Watch the release.** It runs for about 45 minutes. Check that the
   `Select Qualified Prerelease` job summary names the approved candidate:

   ```shell
   gh run list --workflow release.yml --limit 1
   gh run watch <run-id> --exit-status
   ```

5. **Verify publication.** Confirm the GitHub Release has assets and that no
   job failed:

   ```shell
   gh release view "$VERSION" --json isPrerelease,publishedAt,assets --jq '{isPrerelease, publishedAt, assets: (.assets | length)}'
   gh run view <run-id> --json jobs --jq '.jobs[] | select(.conclusion != "success" and .conclusion != "skipped") | "\(.conclusion)\t\(.name)"'
   ```

   `Trigger Wheel Publish` only starts the GitLab pipeline, so confirm that the
   wheel reached PyPI separately.

6. **Close the loop.** Draft a reply to the coordination thread with the release
   link and any PRs deferred to the next train. After approval, move the
   release milestone's open items to the next milestone.

7. **Start the next train.** This is the last duty of this week's captain, not
   the first of next week's. Until the next `-pre.1` exists, Auto-Tag skips.
   Once it does, Auto-Tag cuts `-pre.2` onward every weekday, so next week's
   captain starts Monday with qualified pre-releases. Do it the same day as
   the release. Your week isn't done until the `-pre.1` `Pre-release` run
   passes, or its failure is triaged and handed to next week's captain.

   Agree with the maintainers whether the next train is patch (the default) or
   minor (notable features or planned breaking changes; see the
   [version selection supplement](../../../rfc/0014-release-stability/release-version-selection.md)):

   ```shell
   git log --format=%s --no-merges "$VERSION..origin/main" | sed -E 's/^([a-z]+)(\(.*\))?(!?):.*/\1\3/' | sort | uniq -c
   ```

   Seed it on a `main` commit after `$VERSION`, without a stable tag of its own
   (versioning prefers the stable tag), and with a successful `Release Dev` run.
   `cancelled` means a newer push superseded the run. If nothing has merged
   since the release, wait.

   ```shell
   for sha in $(git rev-list --max-count=10 "$VERSION..origin/main"); do
     state=$(gh run list --workflow release-dev.yml --commit "$sha" --json status,conclusion --jq '.[0] | if .status == "completed" then .conclusion else .status end')
     echo "${sha:0:9} ${state:-none} $(git log -1 --format=%s "$sha")"
   done
   ```

   After approval, push the tag, which starts `Pre-release`. The `-c` and
   `/dev/null` keep `git` from signing the tag and opening an editor:

   ```shell
   NEXT=vX.Y.Z-pre.1
   NEXT_SHA=<main commit>
   git merge-base --is-ancestor "$VERSION" "$NEXT_SHA" || echo "commit does not contain the release"
   git -c tag.gpgSign=false tag "$NEXT" "$NEXT_SHA" </dev/null
   git push origin "refs/tags/$NEXT"
   gh run list --workflow release-prerelease.yml --branch "$NEXT"
   ```

   Watch the run to the end, then tell next week's captain the train is
   running, and which `-pre.1` run to check on Monday.

## Recovery

| Symptom | Action |
|---|---|
| Transient infrastructure failure in a pre-release | After approval, run `gh run rerun <run-id> --failed`, then recheck the candidate. Reply in the failure's `#openshell-triage` thread with the result. |
| Pre-release qualification passed but publication failed | Usually a registry error, such as GHCR `failed to perform "Tag"`. Rerun failed jobs after approval; `Release` won't select the run until it fully passes. |
| Pre-release run ends in `startup_failure` with no jobs | The workflow file is invalid at that commit, for example a missing permission (`v0.1.5-pre.6`). Rerunning won't help. Merge the workflow fix, then tag the next `-pre.N` on it. |
| Code defect in a pre-release | Fix forward (Monday step 5): merge the fix, then tag the next `-pre.N` on it after its `Release Dev` run passes. |
| `Cargo Deny` fails with `error[vulnerability]` | A new RustSec advisory hit a locked dependency; rerunning won't help. Find the IDs with `gh run view <run-id> --log-failed \| grep -E 'ID: RUSTSEC'`, find or open the bump PR, and treat it as a code defect. |
| A pushed `-pre.N` tag started no run | Wait a few minutes and check again. Only after confirming no run exists, and with approval, run `gh workflow run release-prerelease.yml --ref main -f tag="$TAG"`. |
| `Release` fails in `Select Qualified Prerelease` | No candidate qualified, or its evidence expired. Nothing was tagged or published. Fix the train, then dispatch again. |
| `Release` fails in `Write Release Notes` | The GitHub Release isn't created until the notes succeed. After approval, rerun failed jobs. If it keeps failing, check the inference API key and variables named in the job log. |
| `Release` fails after selection, transient | After approval, run `gh run rerun <run-id> --failed`. A stable tag that already points at the selected commit can be retried. |
| `Release` fails after the `Release` job | The GitHub Release exists. A rerun of an npm or snap publish fails if that version already went out. Rerun only jobs that didn't publish, after approval. |
| `Release` stuck queued | Releases queue behind each other. Check for another running `Release` or a GitHub Actions incident before asking a maintainer to cancel. Don't dispatch again. |

## Related

- `release-openshell`: the short procedure behind Tuesday steps 1–5.
- `watch-github-actions`: general `gh run` monitoring and log retrieval.
- `test-release-canary`: diagnose dev artifact smoke-test failures.
- `CI.md`: release workflows, qualification profile, and scanner policies.
- `rfc/0014-release-stability/`: cadence, qualification, and version selection.
