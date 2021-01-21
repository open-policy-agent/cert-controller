package main

import (
	"flag"
	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"time"
)

var (
	certDir        = flag.String("cert-dir", "", "The directory where certs are stored")
	caName         = flag.String("ca-name", "", "The name of the ca cert")
	secretName     = flag.String("secret-name", "", "The name of the secret")
	serviceName    = flag.String("service-name", "", "The name of the service")
	caOrganization = flag.String("ca-organization", "", "The name of the CA organization")
	nameSpace      = flag.String("namespace", "", "The namespace of your service")
	dnsName        = flag.String("dns-name", "", "The dns name of your service <service name>.<namespace>.svc")
	webhookName    = flag.String("webhook-name", "", "Your webhook name")
)

func main() {
	flag.Parse()

	var webhooks = []rotator.WebhookInfo{
		{
			Name: *webhookName,
			Type: rotator.Mutating, // Todo: allow selecting types
		},
	}

	// configure logging.
	logger, _ := zap.NewDevelopment()

	logger.Info("sleeping to demonstrate restart behavior")
	time.Sleep(5 * time.Second)

	logger.Info("starting cert-controller")
	config := ctrl.GetConfigOrDie()
	scheme := runtime.NewScheme()

	_ = clientgoscheme.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(config, ctrl.Options{
		LeaderElection:         false,
		CertDir:                *certDir,
		MapperProvider: func(c *rest.Config) (meta.RESTMapper, error) {
			return apiutil.NewDynamicRESTMapper(c)
		},
	})
	if err != nil {
		logger.Error("unable to start manager", zap.Error(err))
		os.Exit(1)
	}

	// Make sure certs are generated and valid if cert rotation is enabled.
	if err := rotator.AddRotator(mgr, &rotator.CertRotator{
		SecretKey: types.NamespacedName{
			Namespace: *nameSpace,
			Name:      *secretName,
		},
		CertDir:        *certDir,
		CAName:         *caName,
		CAOrganization: *caOrganization,
		DNSName:        *dnsName,
		Webhooks:       webhooks,
	}); err != nil {
		logger.Error("unable to set up cert rotation", zap.Error(err))

		os.Exit(1)
	}

	logger.Info("starting manager")
	hadError := false
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error("problem running manager", zap.Error(err))
		hadError = true
	}

	if hadError {
		logger.Error("Error running manager", zap.Error(err))
		os.Exit(1)
	}
}