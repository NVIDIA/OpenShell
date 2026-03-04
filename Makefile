.PHONY: all docs docs-strict docs-serve docs-clean help

all: help

docs:
	uv run sphinx-build -b html docs _build/docs

docs-strict:
	uv run sphinx-build -b html -W --keep-going docs _build/docs

docs-serve:
	cd docs && uv run sphinx-autobuild . _build/html --port 8001 --open-browser

docs-clean:
	rm -rf _build/docs

help:
	@echo '----'
	@echo 'docs                         - build HTML documentation'
	@echo 'docs-strict                  - build docs with warnings as errors (used in CI)'
	@echo 'docs-serve                   - serve docs locally with live reload on port 8001'
	@echo 'docs-clean                   - remove built documentation'
