KUBERNETES_VERSION ?= 1.37.0
ENVTEST_VERSION ?= v0.24.1

LOCALBIN ?= $(shell pwd)/bin
ENVTEST ?= $(LOCALBIN)/setup-envtest-$(ENVTEST_VERSION)

all: lint test

lint:
	golangci-lint -v run ./... --timeout 5m

test: envtest
	KUBEBUILDER_ASSETS="$$($(ENVTEST) use $(KUBERNETES_VERSION) --bin-dir $(LOCALBIN) -p path)" && \
	export KUBEBUILDER_ASSETS && \
	go test ./... -coverprofile cover.out

envtest: $(ENVTEST)

$(ENVTEST):
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)
	mv $(LOCALBIN)/setup-envtest $@

crds:
	mkdir -p "config/externaldata/crds"
	curl -L -O --output-dir "config/externaldata/crds" "https://raw.githubusercontent.com/open-policy-agent/frameworks/master/constraint/config/crds/externaldata.gatekeeper.sh_providers.yaml"
	curl -L -O --output-dir "config/externaldata/crds" "https://raw.githubusercontent.com/open-policy-agent/frameworks/master/constraint/config/crds/kustomization.yaml"
