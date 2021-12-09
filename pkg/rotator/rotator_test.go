package rotator

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
	"time"

	"github.com/onsi/gomega"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	cr = &CertRotator{
		CAName:         "ca",
		CAOrganization: "org",
		DNSName:        "service.namespace",
	}
	//certValidityDuration = 10 * 365 * 24 * time.Hour
	begin = time.Now().Add(-1 * time.Hour)
	end   = time.Now().Add(certValidityDuration)
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
		t.Error("Generated cert is not valid")
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

	valid, err := ValidCert(caArtifacts.CertPEM, cert, key, cr.DNSName, time.Now().Add(11*365*24*time.Hour))
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

	valid, err := ValidCert(caArtifacts.CertPEM, caArtifacts.CertPEM, caArtifacts.KeyPEM, cr.CAName, time.Now().Add(11*365*24*time.Hour))
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
	populateSecret(cert, key, caArtifacts, secret)
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
	opts := manager.Options{
		MetricsBindAddress: disabledMetrics,
	}
	mgr, err := manager.New(cfg, opts)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating manager")
	return mgr
}

// Verifies certificate bootstrapping and webhook reconciliation.
func TestReconcileValidatingWebhook(t *testing.T) {
	const nsName = "test-reconcile-validating"
	const secretName = "test-secret"
	const whName = "test-validating-webhook"

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	g := gomega.NewWithT(t)
	mgr := setupManager(g)
	c := mgr.GetClient()

	key := types.NamespacedName{Namespace: nsName, Name: secretName}
	rotator := &CertRotator{
		SecretKey: key,
		Webhooks: []WebhookInfo{
			{
				Name: whName,
				Type: Validating,
			},
		},
	}
	err := AddRotator(mgr, rotator)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "adding rotator")

	createSecret(ctx, g, c, key)

	sideEffectNone := admissionv1.SideEffectClassNone
	wh := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: whName,
		},

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
	err = c.Create(ctx, wh)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating webhookConfig")

	wg := StartTestManager(ctx, mgr, g)

	// Wait for certificates to generated
	ensureCertWasGenerated(ctx, g, c, key)

	// Wait for certificates to populated in managed webhookConfigurations
	ensureWebhookPopulated(ctx, g, c, wh)

	// Zero out the certificates, ensure they are repopulated
	resetWebhook(ctx, g, c, wh)

	// Verify certificates are regenerated
	ensureWebhookPopulated(ctx, g, c, wh)
	cancelFunc()
	wg.Wait()
}

// Verifies certificate bootstrapping and webhook reconciliation.
func TestReconcileMutatingWebhook(t *testing.T) {
	const nsName = "test-reconcile-mutating"
	const secretName = "test-secret"
	const whName = "test-mutating-webhook"

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	g := gomega.NewWithT(t)
	mgr := setupManager(g)
	c := mgr.GetClient()

	key := types.NamespacedName{Namespace: nsName, Name: secretName}
	rotator := &CertRotator{
		SecretKey: key,
		Webhooks: []WebhookInfo{
			{
				Name: whName,
				Type: Mutating,
			},
		},
	}
	err := AddRotator(mgr, rotator)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "adding rotator")

	createSecret(ctx, g, c, key)

	sideEffectNone := admissionv1.SideEffectClassNone
	wh := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: whName,
		},

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
	}
	err = c.Create(ctx, wh)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating webhookConfig")

	wg := StartTestManager(ctx, mgr, g)

	// Wait for certificates to generated
	ensureCertWasGenerated(ctx, g, c, key)

	// Wait for certificates to populated in managed webhookConfigurations
	ensureWebhookPopulated(ctx, g, c, wh)

	// Zero out the certificates, ensure they are repopulated
	resetWebhook(ctx, g, c, wh)

	// Verify certificates are regenerated
	ensureWebhookPopulated(ctx, g, c, wh)
	cancelFunc()
	wg.Wait()
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
	const timeout = 15 * time.Second
	const interval = 50 * time.Millisecond
	var secret corev1.Secret
	g.Eventually(func() bool {
		if err := c.Get(ctx, key, &secret); err != nil {
			return false
		}

		return len(secret.Data) > 0
	}, timeout, interval).Should(gomega.BeTrue(), "waiting for certificate generation")
}

func ensureWebhookPopulated(ctx context.Context, g *gomega.WithT, c client.Client, wh interface{}) {
	const timeout = 15 * time.Second
	const interval = 50 * time.Millisecond

	// convert to unstructured object to accept either ValidatingWebhookConfiguration or MutatingWebhookConfiguration
	whu := &unstructured.Unstructured{}
	err := c.Scheme().Convert(wh, whu, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "cannot convert to webhook to unstructured")

	key := client.ObjectKeyFromObject(whu)
	g.Eventually(func() bool {
		if err := c.Get(ctx, key, whu); err != nil {
			return false
		}
		webhooks, found, err := unstructured.NestedSlice(whu.Object, "webhooks")
		if len(webhooks) == 0 || !found || err != nil {
			return false
		}

		for _, w := range webhooks {
			clientConfig, found, err := unstructured.NestedMap(w.(map[string]interface{}), "clientConfig")
			if !found || err != nil || clientConfig["caBundle"] == nil || len(clientConfig["caBundle"].(string)) == 0 {
				return false
			}
		}
		return true
	}, timeout, interval).Should(gomega.BeTrue(), "waiting for webhook reconciliation")
}

func resetWebhook(ctx context.Context, g *gomega.WithT, c client.Client, wh interface{}) {
	// convert to unstructured object to accept either ValidatingWebhookConfiguration or MutatingWebhookConfiguration
	whu := &unstructured.Unstructured{}
	err := c.Scheme().Convert(wh, whu, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "cannot convert to webhook to unstructured")

	key := client.ObjectKeyFromObject(whu)
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := c.Get(ctx, key, whu); err != nil {
			return err
		}

		webhooks, _, err := unstructured.NestedSlice(whu.Object, "webhooks")
		if err != nil {
			return err
		}

		for _, w := range webhooks {
			if err = unstructured.SetNestedField(w.(map[string]interface{}), nil, "clientConfig", "caBundle"); err != nil {
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
