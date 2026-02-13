# Agent Instructions

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on how to perform common operations (building, testing, linting, running components).

## Plans

- Store plan documents in `architecture/plans`.
- When asked to write a plan, write it there without asking for the location.

## Sandbox Infra Changes

- If you change sandbox infrastructure, ensure `mise run sandbox` succeeds.

## Commits

- Always use [Conventional Commits](https://www.conventionalcommits.org/) format for commit messages
- Format: `<type>(<scope>): <description>` (scope is optional)
- Common types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `perf`
- Never mention Claude or any AI agent in commits (no author attribution, no Co-Authored-By, no references in commit messages)

## Pre-commit

- Run `mise run pre-commit` before committing.
- Install the git hook when working locally: `mise generate git-pre-commit --write --task=pre-commit`

## Python

- Always use `uv` for Python commands (e.g., `uv pip install`, `uv run`, `uv venv`)

## Docker

- Always prefer `mise` commands over direct docker builds (e.g., `mise run docker:build` instead of `docker build`)

## Cluster Infrastructure Changes

- If you change cluster bootstrap infrastructure (e.g., `navigator-bootstrap` crate, `Dockerfile.cluster`, `cluster-entrypoint.sh`, `cluster-healthcheck.sh`, deploy logic in `navigator-cli`), update the `debug-navigator-cluster` skill in `.agent/skills/debug-navigator-cluster/SKILL.md` to reflect those changes.

## Documentation

- When making changes, update the relevant documentation in the `architecture/` directory.