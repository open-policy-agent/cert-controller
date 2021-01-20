all: lint test

lint:
	golangci-lint -v run ./... --timeout 5m

test:
	go test ./... -coverprofile cover.out
