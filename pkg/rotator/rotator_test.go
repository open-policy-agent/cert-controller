package rotator

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/onsi/gomega"
	externaldatav1beta1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1beta1"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	ValidCABundle       = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIwekNDQVgyZ0F3SUJBZ0lKQUkvTTdCWWp3Qit1TUEwR0NTcUdTSWIzRFFFQkJRVUFNRVV4Q3pBSkJnTlYKQkFZVEFrRlZNUk13RVFZRFZRUUlEQXBUYjIxbExWTjBZWFJsTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWAphV1JuYVhSeklGQjBlU0JNZEdRd0hoY05NVEl3T1RFeU1qRTFNakF5V2hjTk1UVXdPVEV5TWpFMU1qQXlXakJGCk1Rc3dDUVlEVlFRR0V3SkJWVEVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFaE1COEdBMVVFQ2d3WVNXNTAKWlhKdVpYUWdWMmxrWjJsMGN5QlFkSGtnVEhSa01Gd3dEUVlKS29aSWh2Y05BUUVCQlFBRFN3QXdTQUpCQU5MSgpoUEhoSVRxUWJQa2xHM2liQ1Z4d0dNUmZwL3Y0WHFoZmRRSGRjVmZIYXA2TlE1V29rLzR4SUErdWkzNS9NbU5hCnJ0TnVDK0JkWjF0TXVWQ1BGWmNDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkp2S3M4UmZKYVhUSDA4VytTR3YKelF5S24wSDhNQjhHQTFVZEl3UVlNQmFBRkp2S3M4UmZKYVhUSDA4VytTR3Z6UXlLbjBIOE1Bd0dBMVVkRXdRRgpNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUZCUUFEUVFCSmxmZkpIeWJqREd4Uk1xYVJtRGhYMCs2djAyVFVLWnNXCnI1UXVWYnBRaEg2dSswVWdjVzBqcDlRd3B4b1BUTFRXR1hFV0JCQnVyeEZ3aUNCaGtRK1YKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	gEventuallyTimeout  = 15 * time.Second
	gEventuallyInterval = 50 * time.Millisecond
)

var (
	cr = &CertRotator{
		CAName:         "ca",
		CAOrganization: "org",
		DNSName:        "service.namespace",
		ExtraDNSNames: []string{
			"other-service.namespace",
		},
		ExtKeyUsages: &[]x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	begin          = time.Now().Add(-1 * time.Hour)
	end            = time.Now().Add(defaultCertValidityDuration)
	sideEffectNone = admissionv1.SideEffectClassNone
)

func TestCertSigning(t *testing.T) {
	caArtifacts, err := cr.CreateCACert(begin, end)
	if err != nil {
		t.Fatal(err)
	}

	cert, key, err := cr.CreateCertPEM(caArtifacts, begin, end)
	if err != nil {
		t.Fatal(err)
	}

	if !cr.validServerCert(caArtifacts.CertPEM, cert, key) {
		t.Error("Generated cert is not valid for common name")
	}

	valid, err := ValidCert(caArtifacts.CertPEM, cert, key, cr.ExtraDNSNames[0], cr.ExtKeyUsages, lookaheadTime())
	if err != nil || !valid {
		t.Error("Generated cert is not valid for ExtraDnsName")
	}
}

func TestCertExpiry(t *testing.T) {
	caArtifacts, err := cr.CreateCACert(begin, end)
	if err != nil {
		t.Fatal(err)
	}

	cert, key, err := cr.CreateCertPEM(caArtifacts, begin, end)
	if err != nil {
		t.Fatal(err)
	}

	if !cr.validServerCert(caArtifacts.CertPEM, cert, key) {
		t.Error("Generated cert is not valid")
	}

	valid, err := ValidCert(caArtifacts.CertPEM, cert, key, cr.DNSName, cr.ExtKeyUsages, time.Now().Add(11*365*24*time.Hour))
	if err == nil {
		t.Error("Generated cert has not expired when it should have")
	}
	if valid {
		t.Error("Expired cert is still valid")
	}
}

func TestBadCA(t *testing.T) {
	caArtifacts, err := cr.CreateCACert(begin, end)
	if err != nil {
		t.Fatal(err)
	}

	cert, key, err := cr.CreateCertPEM(caArtifacts, begin, end)
	if err != nil {
		t.Fatal(err)
	}

	badCAArtifacts, err := cr.CreateCACert(begin, end)
	if err != nil {
		t.Fatal(err)
	}

	if cr.validServerCert(badCAArtifacts.CertPEM, cert, key) {
		t.Error("Generated cert is valid when it should not be")
	}
}

func TestSelfSignedCA(t *testing.T) {
	caArtifacts, err := cr.CreateCACert(begin, end)
	if err != nil {
		t.Fatal(err)
	}

	if !cr.validCACert(caArtifacts.CertPEM, caArtifacts.KeyPEM) {
		t.Error("Generated cert is not valid")
	}
}

func TestCAExpiry(t *testing.T) {
	caArtifacts, err := cr.CreateCACert(begin, end)
	if err != nil {
		t.Fatal(err)
	}

	if !cr.validCACert(caArtifacts.CertPEM, caArtifacts.KeyPEM) {
		t.Error("Generated cert is not valid")
	}

	valid, err := ValidCert(caArtifacts.CertPEM, caArtifacts.CertPEM, caArtifacts.KeyPEM, cr.CAName, cr.ExtKeyUsages, time.Now().Add(11*365*24*time.Hour))
	if err == nil {
		t.Error("Generated cert has not expired when it should have")
	}
	if valid {
		t.Error("Expired cert is still valid")
	}
}

func TestSecretRoundTrip(t *testing.T) {
	caArtifacts, err := cr.CreateCACert(begin, end)
	if err != nil {
		t.Fatal(err)
	}

	cert, key, err := cr.CreateCertPEM(caArtifacts, begin, end)
	if err != nil {
		t.Fatal(err)
	}

	if !cr.validServerCert(caArtifacts.CertPEM, cert, key) {
		t.Fatal("Generated cert is not valid")
	}

	secret := &corev1.Secret{}
	populateSecret(cert, key, cr.CertName, cr.KeyName, caArtifacts, secret)
	art2, err := buildArtifactsFromSecret(secret)
	if err != nil {
		t.Fatal(err)
	}

	if !cr.validServerCert(art2.CertPEM, cert, key) {
		t.Fatal("Recovered cert is not valid")
	}

	cert2, key2, err := cr.CreateCertPEM(art2, begin, end)
	if err != nil {
		t.Fatal(err)
	}

	if !cr.validServerCert(caArtifacts.CertPEM, cert2, key2) {
		t.Fatal("Second generated cert is not valid")
	}
}

func TestEmptyIsInvalid(t *testing.T) {
	if cr.validServerCert([]byte{}, []byte{}, []byte{}) {
		t.Fatal("empty cert is valid")
	}
	if cr.validCACert([]byte{}, []byte{}) {
		t.Fatal("empty CA cert is valid")
	}
}

func setupManager(g *gomega.GomegaWithT) manager.Manager {
	disabledMetrics := "0"

	var addToSchemes runtime.SchemeBuilder

	addToSchemes = append(addToSchemes, corev1.AddToScheme)
	addToSchemes = append(addToSchemes, admissionv1.AddToScheme)
	addToSchemes = append(addToSchemes, apiextensionsv1.AddToScheme)
	addToSchemes = append(addToSchemes, apiregistrationv1.AddToScheme)
	addToSchemes = append(addToSchemes, externaldatav1beta1.AddToScheme)

	scheme := runtime.NewScheme()
	err := addToSchemes.AddToScheme(scheme)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "building runtime schema")

	opts := manager.Options{
		Scheme:             scheme,
		MetricsBindAddress: disabledMetrics,
	}
	mgr, err := manager.New(cfg, opts)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating manager")
	return mgr
}

func testWebhook(t *testing.T, secretKey types.NamespacedName, rotator *CertRotator, wh client.Object, webhooksField, caBundleField []string) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	g := gomega.NewWithT(t)
	mgr := setupManager(g)
	c := mgr.GetClient()

	err := AddRotator(mgr, rotator)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "adding rotator")

	createSecret(ctx, g, c, secretKey)

	err = c.Create(ctx, wh)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating webhookConfig")

	wg := StartTestManager(ctx, mgr, g)

	// Wait for certificates to generated
	ensureCertWasGenerated(ctx, g, c, secretKey)

	// Wait for certificates to populated in managed webhookConfigurations
	ensureWebhookPopulated(ctx, g, c, wh, webhooksField, caBundleField)

	// Zero out the certificates, ensure they are repopulated
	resetWebhook(ctx, g, c, wh, webhooksField, caBundleField)

	// Verify certificates are regenerated
	ensureWebhookPopulated(ctx, g, c, wh, webhooksField, caBundleField)

	cancelFunc()
	wg.Wait()
}

func TestReconcileWebhook(t *testing.T) {
	testCases := []struct {
		name          string
		webhookType   WebhookType
		webhooksField []string
		caBundleField []string
		webhookConfig client.Object
	}{
		{"validating", Validating, []string{"webhooks"}, []string{"clientConfig", "caBundle"}, &admissionv1.ValidatingWebhookConfiguration{
			Webhooks: []admissionv1.ValidatingWebhook{
				{
					Name:        "testpolicy.kubernetes.io",
					SideEffects: &sideEffectNone,
					ClientConfig: admissionv1.WebhookClientConfig{
						URL: strPtr("https://localhost/webhook"),
					},
					AdmissionReviewVersions: []string{"v1", "v1beta1"},
				},
			},
		}},
		{"mutating", Mutating, []string{"webhooks"}, []string{"clientConfig", "caBundle"}, &admissionv1.MutatingWebhookConfiguration{
			Webhooks: []admissionv1.MutatingWebhook{
				{
					Name:        "testpolicy.kubernetes.io",
					SideEffects: &sideEffectNone,
					ClientConfig: admissionv1.WebhookClientConfig{
						URL: strPtr("https://localhost/webhook"),
					},
					AdmissionReviewVersions: []string{"v1", "v1beta1"},
				},
			},
		}},
		{"crdconversion", CRDConversion, nil, []string{"spec", "conversion", "webhook", "clientConfig", "caBundle"}, &apiextensionsv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "testcrds.example.com",
			},
			Spec: apiextensionsv1.CustomResourceDefinitionSpec{
				Group: "example.com",
				Scope: apiextensionsv1.NamespaceScoped,
				Names: apiextensionsv1.CustomResourceDefinitionNames{
					Kind:     "TestCRD",
					ListKind: "TestCRDList",
					Plural:   "testcrds",
					Singular: "testcrd",
				},
				Conversion: &apiextensionsv1.CustomResourceConversion{
					Strategy: apiextensionsv1.WebhookConverter,
					Webhook: &apiextensionsv1.WebhookConversion{
						ClientConfig: &apiextensionsv1.WebhookClientConfig{
							URL: strPtr("https://localhost/webhook"),
						},
						ConversionReviewVersions: []string{"v1", "v1beta1"},
					},
				},
				Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
					{
						Name:    "v1alpha1",
						Storage: true,
						Schema: &apiextensionsv1.CustomResourceValidation{
							OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
								Type: "object",
							},
						},
					},
				},
			},
		}},
		{
			"apiservice", APIService, nil, []string{"spec", "caBundle"}, &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "v1alpha1.example.com",
				},
				Spec: apiregistrationv1.APIServiceSpec{
					Group:                "example.com",
					GroupPriorityMinimum: 1,
					Version:              "v1alpha1",
					VersionPriority:      1,
					Service: &apiregistrationv1.ServiceReference{
						Namespace: "kube-system",
						Name:      "example-api",
					},
				},
			},
		},
		{
			"externaldataprovider", ExternalDataProvider, nil, []string{"spec", "caBundle"}, &externaldatav1beta1.Provider{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "externaldata.gatekeeper.sh/v1beta1",
					Kind:       "Provider",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-provider",
				},
				Spec: externaldatav1beta1.ProviderSpec{
					URL:      "https://my-provider:8080",
					Timeout:  10,
					CABundle: ValidCABundle,
				},
			},
		},
	}

	for _, tt := range testCases {
		var (
			secretName = "test-secret"
			whName     = fmt.Sprintf("test-webhook-%s", tt.name)
		)

		// this test relies on the rotator to generate/ rotate the CA
		t.Run(fmt.Sprintf("%s-rotator", tt.name), func(t *testing.T) {
			nsName := fmt.Sprintf("test-reconcile-%s-1", tt.name)
			key := types.NamespacedName{Namespace: nsName, Name: secretName}

			// CRDConversion and APIService require special name format
			if tt.webhookConfig.GetName() != "" {
				whName = tt.webhookConfig.GetName()
			} else {
				whName = whName + "-1"
			}

			rotator := &CertRotator{
				SecretKey: key,
				Webhooks: []WebhookInfo{
					{
						Name: whName,
						Type: tt.webhookType,
					},
				},
			}
			wh, ok := tt.webhookConfig.DeepCopyObject().(client.Object)
			if !ok {
				t.Fatalf("could not deep copy wh object")
			}
			wh.SetName(whName)

			testWebhook(t, key, rotator, wh, tt.webhooksField, tt.caBundleField)
		})

		// this test does not start the rotator as a runnable instead it tests that
		// the webhook reconciler can call on the rotator to refresh/ generate certs as needed.
		t.Run(fmt.Sprintf("%s-without-background-rotation", tt.name), func(t *testing.T) {
			if tt.webhookConfig.GetName() != "" {
				t.Skip("skipping for CRDConversion and APIService")
			}

			nsName := fmt.Sprintf("test-reconcile-%s-2", tt.name)
			key := types.NamespacedName{Namespace: nsName, Name: secretName}
			whName = whName + "-2"

			rotator := &CertRotator{
				SecretKey: key,
				Webhooks: []WebhookInfo{
					{
						Name: whName,
						Type: tt.webhookType,
					},
				},
				testNoBackgroundRotation: true,
				CaCertDuration:           defaultCertValidityDuration,
				ExtKeyUsages:             &[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			wh, ok := tt.webhookConfig.DeepCopyObject().(client.Object)
			if !ok {
				t.Fatalf("could not deep copy wh object")
			}
			wh.SetName(whName)

			testWebhook(t, key, rotator, wh, tt.webhooksField, tt.caBundleField)
		})
	}
}

// TestWebhookCARotation makes sure that a webhook will be able to regenerate/ rotate the CA.
func TestWebhookCARotation(t *testing.T) {
	whName := "test-webhook-validating"
	key := types.NamespacedName{Namespace: "test-reconcile-cert-wh-rotation", Name: "test-secret"}
	rotator := &CertRotator{
		SecretKey: key,
		Webhooks: []WebhookInfo{
			{
				Name: whName,
				Type: Validating,
			},
		},
		testNoBackgroundRotation: true,
		CaCertDuration:           time.Duration(time.Second * 2),
		ExtKeyUsages:             &[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	wh := &admissionv1.ValidatingWebhookConfiguration{
		Webhooks: []admissionv1.ValidatingWebhook{
			{
				Name:        "testpolicy.kubernetes.io",
				SideEffects: &sideEffectNone,
				ClientConfig: admissionv1.WebhookClientConfig{
					URL: strPtr("https://localhost/webhook"),
				},
				AdmissionReviewVersions: []string{"v1", "v1beta1"},
			},
		},
	}
	wh.SetName(whName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gomega.NewWithT(t)
	mgr := setupManager(g)
	c := mgr.GetClient()

	err := AddRotator(mgr, rotator)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "adding rotator")

	createSecret(ctx, g, c, rotator.SecretKey)

	err = c.Create(ctx, wh)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating webhookConfig")
	_ = StartTestManager(ctx, mgr, g)

	// Wait for certificates to generated
	ensureCertWasGenerated(ctx, g, c, rotator.SecretKey)

	// get cert from ca bundle
	var secret1 corev1.Secret
	if err := c.Get(ctx, rotator.SecretKey, &secret1); err != nil {
		t.Fatal("error while getting secret; should not error", err)
	}
	kpa1, err := buildArtifactsFromSecret(&secret1)
	if err != nil {
		t.Fatal(err)
	}

	// trigger a reconcile event and see the CA get expired and rotated
	if secret1.Annotations == nil {
		secret1.Annotations = make(map[string]string)
	}
	secret1.Annotations["test-annon"] = time.Now().GoString()
	if err := c.Update(ctx, &secret1); err != nil {
		t.Fatal("error while updating secret to reconcile; should not error", err)
	}

	g.Eventually(func() bool {
		var secret2 corev1.Secret
		if err := c.Get(ctx, rotator.SecretKey, &secret2); err != nil {
			t.Fatal("error while getting secret; should not error", err)
		}

		// check that the two secrets are not the same
		if reflect.DeepEqual(secret1.Data, secret2.Data) {
			return false
		}

		kpa2, err := buildArtifactsFromSecret(&secret2)
		if err != nil {
			t.Fatal(err)
		}

		// sanity check that the two KPAs are different too:
		if reflect.DeepEqual(kpa1, kpa2) {
			return false
		}

		return true
	}, gEventuallyTimeout, gEventuallyInterval).Should(gomega.BeTrue(), "waiting for webhook reconciliation to rotate a short lived CA")
}

// Verifies that the rotator cache only reads from a single namespace.
func TestNamespacedCache(t *testing.T) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	g := gomega.NewWithT(t)
	mgr := setupManager(g)
	c := mgr.GetClient()

	key := types.NamespacedName{Namespace: "test-namespace-0", Name: "test-secret"}
	rotator := &CertRotator{
		SecretKey: key,
	}
	err := AddRotator(mgr, rotator)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "adding rotator")

	// This secret will be visible to the rotator
	createSecret(ctx, g, c, key)

	// These secrets are in other namespaces and will be ignored
	for i := 1; i < 5; i++ {
		key := types.NamespacedName{Namespace: fmt.Sprintf("test-namespace-%d", i), Name: "test-secret"}
		createSecret(ctx, g, c, key)
	}

	wg := StartTestManager(ctx, mgr, g)

	// The reader (cache) will be initialized in AddRotator.
	g.Expect(rotator.reader).ToNot(gomega.BeNil())

	// Wait for it to populate
	if !rotator.reader.WaitForCacheSync(ctx) {
		t.Fatal("waiting for cache to populate")
	}

	lst := &corev1.SecretList{}
	err = rotator.reader.List(ctx, lst)
	g.Expect(err).ToNot(gomega.HaveOccurred(), "listing secrets")

	g.Expect(lst.Items).To(gomega.HaveLen(1), "expected only single secret")
	g.Expect(lst.Items[0].Namespace).To(gomega.Equal(key.Namespace), "verifying secret namespace")
	g.Expect(lst.Items[0].Name).To(gomega.Equal(key.Name), "verifying secret name")

	cancelFunc()
	wg.Wait()
}

func ensureCertWasGenerated(ctx context.Context, g *gomega.WithT, c client.Reader, key types.NamespacedName) {
	var secret corev1.Secret
	g.Eventually(func() bool {
		if err := c.Get(ctx, key, &secret); err != nil {
			return false
		}

		return len(secret.Data) > 0
	}, gEventuallyTimeout, gEventuallyInterval).Should(gomega.BeTrue(), "waiting for certificate generation")
}

func extractWebhooks(g *gomega.WithT, u *unstructured.Unstructured, webhooksField []string) []interface{} {
	var webhooks []interface{}
	var err error

	if webhooksField != nil {
		webhooks, _, err = unstructured.NestedSlice(u.Object, webhooksField...)
		g.Expect(err).NotTo(gomega.HaveOccurred(), "cannot extract webhooks from object")
	} else {
		webhooks = []interface{}{u.Object}
	}
	return webhooks
}

func ensureWebhookPopulated(ctx context.Context, g *gomega.WithT, c client.Client, wh interface{}, webhooksField, caBundleField []string) {
	// convert to unstructured object to accept either ValidatingWebhookConfiguration or MutatingWebhookConfiguration
	whu := &unstructured.Unstructured{}
	err := c.Scheme().Convert(wh, whu, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "cannot convert to webhook to unstructured")

	key := client.ObjectKeyFromObject(whu)
	g.Eventually(func() bool {
		if err := c.Get(ctx, key, whu); err != nil {
			return false
		}

		webhooks := extractWebhooks(g, whu, webhooksField)
		for _, w := range webhooks {
			caBundle, found, err := unstructured.NestedFieldNoCopy(w.(map[string]interface{}), caBundleField...)
			if !found || err != nil || caBundle == nil || len(caBundle.(string)) == 0 {
				return false
			}
		}
		return true
	}, gEventuallyTimeout, gEventuallyInterval).Should(gomega.BeTrue(), "waiting for webhook reconciliation")
}

func resetWebhook(ctx context.Context, g *gomega.WithT, c client.Client, wh interface{}, webhooksField, caBundleField []string) {
	// convert to unstructured object to accept either ValidatingWebhookConfiguration or MutatingWebhookConfiguration
	whu := &unstructured.Unstructured{}
	err := c.Scheme().Convert(wh, whu, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "cannot convert to webhook to unstructured")

	key := client.ObjectKeyFromObject(whu)
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := c.Get(ctx, key, whu); err != nil {
			return err
		}

		webhooks := extractWebhooks(g, whu, webhooksField)
		for _, w := range webhooks {
			if err = unstructured.SetNestedField(w.(map[string]interface{}), "", caBundleField...); err != nil {
				return err
			}
		}
		return c.Update(ctx, whu)
	})
	g.Expect(err).NotTo(gomega.HaveOccurred(), "resetting webhook")
}

// createSecret creates an empty secret.
// If the referenced namespace does not exist, it will be created.
func createSecret(ctx context.Context, g *gomega.WithT, c client.Writer, secretKey types.NamespacedName) {
	err := c.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: secretKey.Namespace},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating namespace", secretKey.Namespace)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secretKey.Namespace,
			Name:      secretKey.Name,
		},
	}
	err = c.Create(ctx, secret)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating secret", secretKey)
}

func strPtr(s string) *string {
	return &s
}
