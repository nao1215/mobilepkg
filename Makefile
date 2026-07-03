.PHONY: build test e2e lint clean tools install

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
	./e2e/run.sh

lint:
	golangci-lint run ./...

clean:
	rm -f $(APP) cover.out cover.html

tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
