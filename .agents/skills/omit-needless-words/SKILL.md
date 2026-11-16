---
name: omit-needless-words
description: Use when reviewing a PR, branch, diff, doc, skill, or comment block for wordiness, history or roadmap prose, restated information, or code and tests beyond what the spec asks for.
metadata:
  internal: true
---

# Omit Needless Words

Review changed prose and code against five rules. The review obeys them too.

## The Rules

1. **Crisp.** Docs, skills, and comments use the fewest words that carry the meaning.
2. **Present tense.** Say what the code or skill does now. History ("used to", "no longer", "still", "is never edited") and roadmap ("pending", "temporary", "will", "once X lands") belong in PRs and issues.
3. **Earned words.** Add words only where the code or existing text doesn't already say it. A comment that restates the next line, or a README that re-describes a function, is a finding.
4. **DRY.** Each fact lives in one place; everything else links to it. Defaults, rules, and contracts written in multiple places will drift.
5. **AMANALAP.** As much as needed, as little as possible. Code and tests answer to the spec, don't add things it doesn't ask for.

## Process

1. **Target:** the PR, branch, path, or diff given; otherwise the current branch against its base. Read the whole diff. Read PR files with `gh pr diff` and `gh api repos/OWNER/REPO/contents/PATH?ref=HEAD_SHA`; the review leaves every checkout and ref as it found them.
2. **Spec:** find what the change answers to: linked issue, RFC, design doc, or PR body. Rule 5 is measured against it. With no spec, judge rule 5 against the PR's stated purpose.
3. **Check context before calling something new:** a deleted file is a removal, not a duplicate; a fact in an existing doc is the canonical copy.
4. **Apply the rules with these conditionals:**
   - If a comment states *why* (an invariant, an external constraint, a deliberate absence such as "never retries"), it is earned (rule 3 passes). If it states *what* the adjacent code does, it is a finding.
   - If code validates untrusted input, enforces auth, or bounds external responses, time, or cost, it is needed (rule 5 passes).
   - If the spec requires a copy (man page, `--help`, published docs), that copy stays; the finding is that the *other* copies link to the canonical one.
   - If text is in a PR body or commit message, rule 2 does not apply.
   - If an issue is a correctness bug or design flaw that none of the five rules covers, it belongs in a separate review; leave it out of this one.

## Output

The review is exactly:

```
**Verdict:** <one sentence: how much should go, and the biggest reason>

1. `path:line` — [rule #] <problem in one sentence>
   **Fix:** <replacement text in quotes, "Delete.", or "Link to `path#anchor`.">
2. ...
```

- Order findings by how much text or code the fix removes, largest first.
- One finding per distinct problem; group identical problems (e.g. five copies of one rule) into one finding listing every location.
- Each Fix is concrete enough to apply without rereading the diff.
- Tone is blunt and flat: state the problem, give the fix.
- When nothing violates the rules, the review is the verdict line alone.
