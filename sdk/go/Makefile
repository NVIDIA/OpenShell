MISE := $(shell command -v mise 2>/dev/null)

.PHONY: test test-integration lint fmt build ci docs-check

test:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run test

test-integration:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run test:integration

lint:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run lint

fmt:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run fmt

build:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run build

ci:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run ci

docs-check:
ifndef MISE
	$(error mise is not installed. Install from https://mise.jdx.dev)
endif
	mise run docs:check
