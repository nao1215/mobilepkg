.PHONY: test lint clean tools

test:
	go test -v -count=1 -coverprofile=cover.out ./...
	go tool cover -html=cover.out -o cover.html

lint:
	golangci-lint run ./...

clean:
	rm -f cover.out cover.html *.test

tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
