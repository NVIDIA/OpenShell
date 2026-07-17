MISE := $(shell command -v mise 2>/dev/null)

.PHONY: test test-integration lint fmt build ci docs-check

test:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run go:test

test-integration:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run go:test:integration

lint:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run go:lint

fmt:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run go:fmt

build:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run go:build

ci:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run go:ci

docs-check:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run go:docs:check
