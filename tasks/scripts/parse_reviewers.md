# Reviewer registry parser

`parse_reviewers.py` provides an offline Python API and a JSON CLI for
[`REVIEWERS.md`](../../REVIEWERS.md). It uses only the Python standard library.
It reads membership, category labels, and scope descriptions. Repository roles,
permission checks, reviewer selection, notifications, and approval requirements
belong to consumers of this data.

Validate the registry:

```shell
uv run --no-project tasks/scripts/parse_reviewers.py --reviewers REVIEWERS.md --check
```

Export JSON:

```shell
uv run --no-project tasks/scripts/parse_reviewers.py --reviewers REVIEWERS.md
```

Run the focused tests:

```shell
mise run test:reviewers
```

## Supported format

- Categories use level-three headings such as `### area:runtime` under `## Areas`
  or `### topic:policy` under `## Topics`. Labels use lowercase letters, digits,
  and hyphen-separated words. Category labels are unique.
- Each category has a nonempty scope description followed by one contiguous
  table with exactly `Name`, `GitHub ID`, and `Company/Organization` columns.
- Tables use leading and trailing pipes. Separator alignment markers and escaped
  pipes in values are supported. Names and organizations must be nonempty.
- The GitHub ID is a link such as `[@Alice](https://github.com/alice)` whose
  displayed handle matches the profile path, case-insensitively. A trailing slash
  on the profile URL is accepted. Stored logins are lowercase.
- A person may belong to several categories. Duplicate handles within one
  category are errors, including duplicates with different capitalization.
- An explicitly empty membership table is valid. Coverage requirements are
  separate from syntax validation and need repository permission information.
- Profile links in prose, code examples, or HTML comments do not add members.
  The parser does not support arbitrary Markdown table extensions, reference
  links, or HTML tables.

## Python API and JSON contract

`parse_reviewers(markdown)` returns a tuple of immutable `Category` records.
Each record contains `label`, `description`, and a tuple of `Member` records.
Members contain `name`, `login`, and `organization`. Category/member order follows
the document; descriptions retain Markdown text and paragraph breaks.

The CLI emits this versioned structure:

```json
{
  "schema_version": 1,
  "categories": [
    {
      "label": "area:runtime",
      "description": "Workload execution.",
      "members": [
        {"name": "Alice", "login": "alice", "organization": "Example"}
      ]
    }
  ]
}
```

Consumers can look up categories, combine/deduplicate their member sets, reverse
the mapping to find a person's memberships, or compare two parsed versions to
report membership changes. Empty categories produce an empty `members` array.

Malformed registries raise `RegistryError` in Python. The CLI reports the input
path and diagnostic on stderr, exits nonzero, and emits no partial JSON. Structural
errors include a source line number. `--check` prints a validation summary instead
of JSON. Missing or unreadable input also exits nonzero.

For operational routing or approval decisions, read both the helper and registry
from a trusted merged ref, as the existing maintainer-approval check does. Parsing
a proposed PR version is useful for reporting changes; it does not authorize
that proposed membership to review the same PR.
