VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GO ?= go

.PHONY: build test integration vet clean cross docker docker-scan selftest install install-server bind-tools bind-check bind-ios bind-android

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/cpprobe ./cmd/cpprobe

test:
	$(GO) test ./... -count=1

integration:
	$(GO) test ./internal/integration/ -count=1 -v -run .

vet:
	$(GO) vet ./...

# Static binaries for the usual targets (server on cloud VMs, client on laptops).
cross:
	@mkdir -p dist
	for os in linux darwin; do for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/cpprobe-$$os-$$arch ./cmd/cpprobe; \
	done; done
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/cpprobe-windows-amd64.exe ./cmd/cpprobe
	ls -la dist

# Mobile bindings of the engine (bind/): an xcframework for iOS and an AAR
# for Android. gomobile and gobind are tool dependencies of go.mod (pinned
# by go.sum, run as `go tool gomobile`), so CI and a laptop build with the
# same version. gomobile looks gobind up on PATH: bind-tools builds the
# pinned one into bin/. iOS needs Xcode; Android needs the NDK
# (ANDROID_NDK_HOME, or the newest under $ANDROID_HOME/ndk).
BIND_LDFLAGS := -X github.com/xarvel/CensorPulseCli/engine.Version=$(VERSION)
GOMOBILE := PATH="$(CURDIR)/bin:$$PATH" $(GO) tool gomobile

bind-tools:
	@mkdir -p bin
	$(GO) build -o bin/gobind golang.org/x/mobile/cmd/gobind

# Catches an export gomobile cannot bind, without the NDK or Xcode. gobind
# does not fail on one: it drops the symbol and leaves a "// skipped ..."
# comment in the generated code, so the check greps for that.
bind-check:
	@d="$$(mktemp -d)" && $(GO) tool gobind -lang=go,java,objc -outdir "$$d" ./bind && \
	if grep -rn "^// skipped " "$$d"; then echo "bind/: gomobile cannot bind the exports above" >&2; exit 1; fi && \
	rm -rf "$$d" && echo "bind-check: ok"

bind-ios: bind-tools
	@mkdir -p dist
	$(GOMOBILE) bind -target ios,iossimulator -iosversion 15.0 -o dist/Cpprobe.xcframework -ldflags="$(BIND_LDFLAGS)" ./bind

bind-android: bind-tools
	@mkdir -p dist
	$(GOMOBILE) bind -target android/arm64,android/arm,android/amd64 -androidapi 24 -o dist/cpprobe.aar -ldflags="$(BIND_LDFLAGS)" ./bind

# Client: install build prerequisites if missing, build, install cpprobe.
install:
	sh scripts/install.sh

# Server: install Docker if missing, free port 53, start with docker compose.
install-server:
	sudo sh scripts/install-server.sh

docker:
	docker build --build-arg VERSION=$(VERSION) -t censorpulse-probe:$(VERSION) .

# Run the client from Docker: make docker-scan ARGS="--target 203.0.113.10 --pin '...'"
docker-scan:
	CPPROBE_IMAGE=censorpulse-probe:$(VERSION) sh scripts/scan-docker.sh $(ARGS)

# Start a throwaway server on high ports and scan it from the same host.
selftest: build
	./scripts/selftest.sh

clean:
	rm -rf bin dist
