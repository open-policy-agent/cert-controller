# Certificate Controller

## Purpose

The purpose of the Certificate Controller library is to provide
an easy way for controller authors to bootstrap webhooks while
making it possible for users to use more customizable projects like
[cert-manager](https://cert-manager.io/docs/) should they desire
to do so. Its purpose is not to be a fully-featured certificate
solution, but a simple solution that allows webhook authors to avoid
having a hard dependency on the existence of any third-party
certificate generation solution.

This library was originally written as part of Gatekeeper to replace
the certificate generation functionality provided by controller-runtime
that was removed as part of a migration to Kubebuilder 2.0. It was then
spun off as a separate repo so that other projects, such as
[Hierarchical Namespace Controller](https://github.com/kubernetes-sigs/multi-tenancy/tree/master/incubator/hnc)
could avoid maintaining duplicate code.

## Design

All behavior is governed by a `CertRotator` object that has two
main control loops:

   1. A tick-based control loop that periodically examines the certificates stored
      in the secret and makes sure they are still valid, regenerating them if not
   2. A watch-based control loop that watches relevant webhook resources and the
      certificate secret. Whenever any of these resources change, the controller
      runs a reconcile to make sure all objects agree on the correct cert, as defined
      by the secret.

The secret is where all certificates are stored and is considered the source of truth.
All resources will be reconciled to match the secret.

## Usage

The following code snippet is taken from the Gatekeeper project:

```
	// Make sure certs are generated and valid if cert rotation is enabled.
	setupFinished := make(chan struct{})
	if !*disableCertRotation && operations.IsAssigned(operations.Webhook) {
		setupLog.Info("setting up cert rotation")
		if err := rotator.AddRotator(mgr, &rotator.CertRotator{
			SecretKey: types.NamespacedName{
				Namespace: util.GetNamespace(),
				Name:      secretName,
			},
			CertDir:        *certDir,
			CAName:         caName,
			CAOrganization: caOrganization,
			DNSName:        dnsName,
			IsReady:        setupFinished,
			VWHName:        vwhName,
		}); err != nil {
			setupLog.Error(err, "unable to set up cert rotation")
			os.Exit(1)
		}
	} else {
		close(setupFinished)
	}
```

The basic pattern is to call `AddRotator`, which adds `CertRotator`
to the controller-runtime manager, where it behaves like a standard controller.

The channel passed to `IsReady` is closed when the certificate has been
fully bootstrapped into local storage. This can be used to delay the
registration of webhooks until a certificate is available to be loaded. This
prevents any crashing of the webhook pod during startup.

Users who set the `RestartOnSecretRefresh` field on the `CertRotator` struct will have the Pod
restart when the cert refreshes or is initialized. This may improve mean
time to availability of a bootstrapping webhook.

## Questions?

If you have questions about the project, please file a GitHub issue.