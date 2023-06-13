package rotator

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/onsi/gomega"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var cfg *rest.Config

// TestMain runs before package tests and starts a local apiserver instance.
func TestMain(m *testing.M) {
	t := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "externaldata", "crds")},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	if cfg, err = t.Start(); err != nil {
		log.Fatal(err)
	}

	code := m.Run()
	if err := t.Stop(); err != nil {
		log.Fatal(fmt.Errorf("shutting down: %w", err))
	}
	os.Exit(code)
}

// StartTestManager adds recFn.
func StartTestManager(ctx context.Context, mgr manager.Manager, g *gomega.GomegaWithT) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.Expect(mgr.Start(ctx)).NotTo(gomega.HaveOccurred())
	}()
	return wg
}
