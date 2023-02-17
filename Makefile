all: lint test

lint:
	golangci-lint -v run ./... --timeout 5m

test:
	go test ./... -coverprofile cover.out

crds:
	mkdir -p "config/externaldata/crds"
	curl -L -O --output-dir "config/externaldata/crds" "https://raw.githubusercontent.com/open-policy-agent/frameworks/master/constraint/config/crds/externaldata.gatekeeper.sh_providers.yaml"
	curl -L -O --output-dir "config/externaldata/crds" "https://raw.githubusercontent.com/open-policy-agent/frameworks/master/constraint/config/crds/kustomization.yaml"
