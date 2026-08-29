.PHONY: build test e2e coverage lint clean tools install

APP      = mobilepkg
VERSION  = $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
LDFLAGS  = -ldflags '-X github.com/nao1215/mobilepkg/internal/cmdinfo.Version=$(VERSION)'

build:
	env GO111MODULE=on go build $(LDFLAGS) -o $(APP) ./cmd/mobilepkg

install:
	env GO111MODULE=on go install $(LDFLAGS) ./cmd/mobilepkg

test:
	go test -v -count=1 -coverprofile=cover.out ./...
	go tool cover -html=cover.out -o cover.html

e2e:
	go run ./e2e/runner

coverage:
	bash ./scripts/coverage.sh

lint:
	golangci-lint run ./...

clean:
	rm -f $(APP) cover.out cover.html coverage.out
	rm -rf .coverage

tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	# @latest on purpose: locally we want to find out immediately when a new
	# atago breaks a spec. CI pins an exact version (see the "Install atago"
	# step in .github/workflows/) so a build stays reproducible.
	go install github.com/nao1215/atago@latest
