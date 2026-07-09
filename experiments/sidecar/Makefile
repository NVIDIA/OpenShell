IMAGE ?= ghcr.io/nvidia/openshell/sidecar-readiness:latest

.PHONY: all build image push

all: build image push

build:
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o readiness-sidecar main.go

image:
	podman build -t $(IMAGE) .

push:
	podman push $(IMAGE)
