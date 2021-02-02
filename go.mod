module github.com/open-policy-agent/cert-controller

go 1.14

require (
 	github.com/go-logr/zapr v0.1.0
	github.com/onsi/gomega v1.10.2
    github.com/open-policy-agent/cert-controller v0.1.0
	github.com/pkg/errors v0.9.1
	go.uber.org/atomic v1.6.0
    go.uber.org/zap v1.10.0
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v0.19.2
	sigs.k8s.io/controller-runtime v0.7.0
)
