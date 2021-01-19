package main

import (
	"flag"
	"fmt"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
	"os"
	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	ctrl "sigs.k8s.io/controller-runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

var (
	certDir        = flag.String("cert-dir", "/etc/tls-certs", "The directory where certs are stored, defaults to /certs")
	caName         = flag.String("ca-name", "ca-name", "The name of the ca cert, defaults to ca-name")
	secretName     = flag.String("secret-name", "secret-name", "The name of the secret, defaults to secret-name")
	serviceName    = flag.String("service-name", "webhook-service-name", "The name of the service, defaults to webhook-service-name")
	caOrganization = flag.String("caOrganization", "organization", "The name of the CA organization, defaults to organization")
	nameSpace      = flag.String("namespace", "kube-system", "The namespace of your service, defaults to kube-system")
	dnsName        = flag.String("dns-name", *serviceName + "." + *nameSpace + ".svc", "The dns name of your service <service name>.<namespace>.svc")
	webhookName    = flag.String("webhook-name", "webhook-name", "Your webhook name, defaults to webhook-name")
)

var webhooks = []rotator.WebhookInfo{
	{
		Name: *webhookName,
		Type: rotator.Mutating, // Todo: allow selecting types
	},
}

// TODO: print when it updates the secrets
// TODO: add a nice logger
// TODO: remove all the default values, PR to cert-controller say this is a POC to run as a standalone
// TODO: put all the vpa values in there
func main() {
	fmt.Println("starting")
	config := ctrl.GetConfigOrDie()
	scheme := runtime.NewScheme()

	_ = clientgoscheme.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:                 scheme, //TODO: try to remove
		MetricsBindAddress:     "0", //TODO: try to remove
		LeaderElection:         false,
		Port:                   443, //TODO: try to remove
		CertDir:                *certDir,
		HealthProbeBindAddress: ":9090", //TODO: try to remove
		MapperProvider: func(c *rest.Config) (meta.RESTMapper, error) {
			return apiutil.NewDynamicRESTMapper(c)
		},
	})
	if err != nil {
		fmt.Println("unable to start manager:", err)
		os.Exit(1)
	}

	// Make sure certs are generated and valid if cert rotation is enabled.
	fmt.Println("setting up cert rotation")
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
		fmt.Println("unable to set up cert rotation:", err)
		os.Exit(1)
	}

	fmt.Println("starting manager")
	hadError := false
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fmt.Println("problem running manager:", err)
		hadError = true
	}

	// Manager stops controllers asynchronously.
	// Instead, we use ControllerSwitch to synchronously prevent them from doing more work.
	// This can be removed when finalizer and status teardown is removed.
	fmt.Println("disabling controllers...")
	// sw.Stop() TODO: see if this is safely deleted

	if hadError {
		fmt.Println("had error:", err)
		os.Exit(1)
	}
}