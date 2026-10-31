---
name: release-captain
description: Run the weekly OpenShell release captain checklist. Monday checks the pre-release train, triages failures and the compatibility review, and drafts the coordination post. Tuesday promotes the qualified pre-release after approval, verifies publication, and starts the next train. Trigger keywords - release captain, weekly release, Tuesday release, cut the release, release checklist, pre-release status, release train, start next train, stable release.
metadata:
  internal: true
---

# Release Captain

OpenShell publishes a stable release every Tuesday from a qualified
pre-release ([RFC 0014](../../../rfc/0014-release-stability/README.md)). The
release captain keeps the week's pre-release train green, coordinates the last
merges, cuts the release, and starts the next train.

## How to use this skill

| When | Ask | What happens |
|---|---|---|
| The week before your turn | "I'm release captain next week. Is the train ready?" | Checks that the next version's `-pre.1` exists. If not, ask this week's captain to start the train (Tuesday step 6). Then check each weekday that Auto-Tag's pre-release ran and passed (`gh run list --workflow release-prerelease.yml --limit 3`), and fix failures as they happen (Monday step 3) instead of on Monday. |
| Monday | "Run the release captain Monday checklist." | Monday steps 1–4. |
| A pre-release failed | "`vX.Y.Z-pre.N` failed, help me fix it." | Monday step 3 and Recovery. |
| Tuesday | "Cut the release." | Tuesday steps 1–6, ending with starting the next train. |

## Guardrails

Get explicit approval, with the exact command and target SHA, before pushing a
tag, dispatching, rerunning, or cancelling a workflow, merging or approving a
PR, or posting in Slack or GitHub. Never repoint a stable tag, delete a `-pre.N`
tag, or start a second `Pre-release` run for a tag; it has no concurrency guard.

## How the train works

- A train has one base version, such as `v0.1.4`, fixed by its `-pre.1` tag. A
  patch train can't take breaking changes to Stable interfaces.
- `Release Auto-Tag` runs on weekdays at 14:00 Europe/Zurich. If `main` has
  commits since the latest `-pre.N`, it tags the next one and dispatches
  `Pre-release` (`release-prerelease.yml`, about 45 minutes). It skips when the
  train has no `-pre.1` or the base version is already stable.
- `Pre-release` builds, then publishes and qualifies in parallel, and writes a
  `release-notes` preview artifact. Pushing a `-pre.N` tag by hand starts it.
- `Release` (`release.yml`) is dispatched by hand with the stable version. It
  picks the highest `-pre.N` on `main` whose whole `Pre-release` run passed,
  creates the stable tag on that commit, and publishes without requalifying.

## Setup

```shell
export GH_REPO=NVIDIA/OpenShell
git fetch origin main --tags --force
PREV=$(git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
git tag -l 'v*' --sort=-v:refname | grep -E -- '-pre\.[0-9]+$' | head -5
```

Find the `Pre-release` run for a tag. A tag pushed by hand runs on the tag; an
Auto-Tag run is dispatched on `main`:

```shell
TAG=vX.Y.Z-pre.N
gh run list --workflow release-prerelease.yml --branch "$TAG"
gh run list --workflow release-prerelease.yml --event workflow_dispatch --commit "$(git rev-parse "$TAG^{commit}")"
```

Preview the candidate `Release` would promote, read-only:

```shell
VERSION=vX.Y.Z
wt=$(mktemp -d)
git worktree add -q --detach "$wt" origin/main
(cd "$wt" && GITHUB_REPOSITORY=NVIDIA/OpenShell uv run -q --no-project python tasks/scripts/select-release-candidate.py "$VERSION" --branch main | jq .)
git worktree remove --force "$wt"
```

## Monday: pre-flight

1. **Check the candidate.** Run the preview. If the latest `-pre.N` isn't the
   candidate, its run failed; read why:

   ```shell
   RUN=<run-id>
   gh run view "$RUN" --json jobs --jq '.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out") | "\(.name)\t\(.url)"'
   gh run view "$RUN" --log-failed
   ```

   If the next version has no `-pre.1`, start the train (Tuesday step 6).

2. **Triage the compatibility review** for the candidate's run. It's advisory,
   and a green job doesn't mean it found no breaks:

   ```shell
   ATTEMPT=$(gh run view "$RUN" --json attempt --jq .attempt)
   dir=$(mktemp -d)
   gh run download "$RUN" -n "compatibility-review-run-$RUN-attempt-$ATTEMPT" -D "$dir"
   jq '{status, verdict: .review.verdict}' "$dir/report.json"
   cat "$dir/report.md"
   ```

   Only `complete` with `no_unaddressed_breaks` is clean. A real break needs a
   fix, a revert, a minor train, or a maintainer-approved exception with upgrade
   steps in the release notes.

3. **Fix forward.** A failed pre-release doesn't end the train. Find the cause,
   and let the failed run finish rather than cancelling it.

   A rerun repeats the same commit and workflow, so it only helps with a
   transient failure (see Recovery). Anything that needs a code or workflow
   fix ships in a new number: that `-pre.N` stays failed, and `Release` skips
   it. Merge the fix, then cut the next `-pre.N` from the tip of `main` after
   approval:

   ```shell
   gh workflow run release-auto-tag.yml --ref main
   ```

   Tag a specific commit by hand (as in Tuesday step 6) only when the tip of
   `main` isn't the commit you want.

4. **Draft the coordination post.** Start a thread in the OpenShell channel of
   the CNCF Slack. The release ships from `main` with no release branch, so the
   thread is for getting ready PRs reviewed and merged before the cutoff. List
   approved PRs:

   ```shell
   gh pr list --base main --state open --search "review:approved" --json number,title,author --jq '.[] | "#\(.number) \(.title) (@\(.author.login))"'
   ```

   The release ships the final pre-release's commit, if it passes. Pick a
   cutoff before Tuesday's Auto-Tag run, or a later one after which you tag the
   final pre-release by hand. Don't promise that everything merged by the
   cutoff ships, or name the next version.

   ```text
   :thread: OpenShell vX.Y.Z release, Tuesday <date>. I'm release captain this week.

   Status: vX.Y.Z-pre.N (<commit>) passed qualification. <blockers and owners, or "No blockers.">

   Reply here with any ready PRs you'd like in vX.Y.Z. Merge cutoff is <HH:MM UTC> (<local time>) Tuesday. <"Tuesday's automatic pre-release picks up everything merged by then" | "I'll cut the final pre-release after the cutoff">, and vX.Y.Z ships from it if it passes qualification. Anything that misses it goes in the next release.
   ```

   If the pre-release that ships was cut before the posted cutoff, say so in
   the thread, with its commit and time.

## Tuesday: cut the release

1. **Select the final candidate.** For a late cutoff, cut the final `-pre.N`
   after the cutoff as in Monday step 3. When it finishes, run the preview and
   repeat Monday step 2 for its run.

2. **Request approval.** Present the candidate tag, commit, qualification run,
   compatibility assessment, commits since `$PREV`, and release notes preview:

   ```shell
   git log --oneline --no-merges "$PREV..<candidate_tag>"
   gh run download "$RUN" -n release-notes -D "$dir/notes" && cat "$dir/notes/release-notes.md"
   ```

   The notes come from each PR's "Release Notes" section. To fix them, edit the
   PR, then preview with
   `gh workflow run release.yml --ref main -f tag="$VERSION" -f notes-only=true`.

3. **Dispatch the release.** After approval:

   ```shell
   gh workflow run release.yml --ref main -f tag="$VERSION"
   ```

4. **Watch and verify.** Check that `Select Qualified Prerelease` names the
   approved candidate, the GitHub Release has assets, no job failed, and the
   wheel reached PyPI:

   ```shell
   gh run watch <run-id> --exit-status
   gh release view "$VERSION" --json isPrerelease,publishedAt,assets --jq '{isPrerelease, publishedAt, assets: (.assets | length)}'
   ```

5. **Close the loop.** Draft a short reply to the coordination thread. Point
   to the release notes rather than repeating them:

   ```text
   :white_check_mark: :ship: OpenShell vX.Y.Z is out: https://github.com/NVIDIA/OpenShell/releases/tag/vX.Y.Z

   It shipped from vX.Y.Z-pre.N (<commit>). I'll be starting the <next version>-pre.* jobs shortly for next week.

   Please check the release notes for upgrade notes that operators might care about. I'm also moving everything still open in the X.Y.Z milestone to <next milestone>.

   Thanks everyone!
   ```

   After approval, move the milestone's open items to the next milestone.

6. **Start the next train.** This is this week's captain's last duty. Until the
   next `-pre.1` exists, Auto-Tag skips. Agree with the maintainers on patch
   (the default) or minor
   ([version selection](../../../rfc/0014-release-stability/release-version-selection.md)).
   Seed it on a commit after `$VERSION` with a passing `Release Dev` run:

   ```shell
   for sha in $(git rev-list --max-count=10 "$VERSION..origin/main"); do
     state=$(gh run list --workflow release-dev.yml --commit "$sha" --json status,conclusion --jq '.[0] | if .status == "completed" then .conclusion else .status end')
     echo "${sha:0:9} ${state:-none} $(git log -1 --format=%s "$sha")"
   done
   ```

   After approval, push the tag. The `-c` and `/dev/null` keep `git` from
   signing the tag and opening an editor:

   ```shell
   NEXT=vX.Y.Z-pre.1 NEXT_SHA=<commit>
   git -c tag.gpgSign=false tag "$NEXT" "$NEXT_SHA" </dev/null
   git push origin "refs/tags/$NEXT"
   ```

   You're done when that `Pre-release` run passes, or its failure is handed to
   next week's captain.

## Recovery

| Symptom | Action |
|---|---|
| Transient infrastructure failure in a pre-release, including a registry push | After approval, `gh run rerun <run-id> --failed`. `Release` won't select the run until all of it passes. |
| Pre-release run ends in `startup_failure` | The workflow file is invalid at that commit. Fix it in a new `-pre.N` (Monday step 3). |
| Code defect or `Cargo Deny` advisory | Rerunning won't help. Fix it in a new `-pre.N` (Monday step 3). |
| `Release` fails after selection | After approval, rerun only the failed jobs that haven't published. |

## Related

- `release-openshell`: the short procedure behind Tuesday steps 1–4.
- `watch-github-actions`: general `gh run` monitoring and log retrieval.
- `CI.md`: release workflows, qualification profile, and scanner policies.
