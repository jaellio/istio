# Pilot CA and RA

This document describes the high level architecture of Istiod's Certificate Authority (CA) and Registration Authority (RA) configuration and Certificate Signing Request (Istio CSR) workflow. It describes the high level components and settings required to support Istiod and workload certificate request authentication, authorization, and issuance.

## High level overview

> Note: This document focusses on the enablement and disablement or the CA or RA and the Istio CSR workflow. It does not explore a possible CA configurations supported by Istio and is not meant to function as a "How to" guide for configuring the CA or RA. Please visit [istio.io]() for guide on how to configure Istio.

At a high level, Istiod can serve as CA or RA and supports integrations custom CAs via the kubernetes CSR api, for example. Istio relies on the trusted identities provided the CA to establish secure, encrypted communication between Istiod and other components and from workload to workload in the service mesh. 

To provision certificates Istiod and related webhooks, Istiod will make internal CSR request or requests to the custom CA. Depending on the environment and variables set on install, Istiod will expose a gRPC service to accept Istio CSR requests from an istio-agent. More on the istio-agent and generation of Istio CSRs can be found in the [istio-agent architecture doc](/architecture/security/istio-agent.md).

## High level components

### Chiron

Internal package that prrovides the functionality to create a certificiate, create a Kubernetes CSR resource, approve a CSR, read the signed certificate, and clean up the remaining artifacts. The package is utilized when the Kubernetes CA is configured as the certificate authority for Istiod. The certificate creation logic is also leveraged by the Certificate Controller which is responsible for generating a new root certificate when Istiod is functioning as the CA and a istiod-generated self-signed root certificate is in use.

### Kubernetes CSR

Kubernetes' documentation for [CSRs](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#certificate-signing-requests).

[Custom CA integration using Kubernetes CSR](https://istio.io/latest/docs/tasks/security/cert-management/custom-ca-k8s/).

### Istio CSR

Proto buffer definition of a Certificate Signing Request. Defined by [ca.proto](). Used by the istio-agent and istiod to communicate desired cert information and issuer.

```proto
// Certificate request message. The authentication should be based on:
// 1. Bearer tokens carried in the side channel;
// 2. Client-side certificate via Mutual TLS handshake.
// Note: the service implementation is REQUIRED to verify the authenticated caller is authorize to
// all SANs in the CSR. The server side may overwrite any requested certificate field based on its
// policies.
message IstioCertificateRequest {
  // PEM-encoded certificate request.
  // The public key in the CSR is used to generate the certificate,
  // and other fields in the generated certificate may be overwritten by the CA.
  string csr = 1;
  // Optional: requested certificate validity period, in seconds.
  int64 validity_duration = 3;

  // $hide_from_docs
  // Optional: Opaque metadata provided by the XDS node to Istio.
  // Supported metadata: WorkloadName, WorkloadIP, ClusterID
  google.protobuf.Struct metadata = 4;
}
```

### CertificateAuthority

Internal interface that defines methods to be supported by a CA type. Implemented by `IstioCA` and `KubernetesRA`.

```go
// CertificateAuthority contains methods to be supported by a CA.
type CertificateAuthority interface {
    // Sign generates a certificate for a workload or CA, from the given CSR and cert opts.
    Sign(csrPEM []byte, opts ca.CertOpts) ([]byte, error)
    // SignWithCertChain is similar to Sign but returns the leaf cert and the entire cert chain.
    SignWithCertChain(csrPEM []byte, opts ca.CertOpts) ([]string, error)
    // GetCAKeyCertBundle returns the KeyCertBundle used by CA.
    GetCAKeyCertBundle() *util.KeyCertBundle
}
```

### CA/RA Server

The CA or RA services are represented using the same internal type, `Server`. `ca` is set to either `IstioCA` or `KubernetesRA`.

```go
// Server implements IstioCAService and IstioCertificateService and provides the services on the
// specified port.
type Server struct {
    pb.UnimplementedIstioCertificateServiceServer
    monitoring     monitoringMetrics
    Authenticators []security.Authenticator
    ca             CertificateAuthority
    serverCertTTL  time.Duration


    nodeAuthorizer *NodeAuthorizer
}
```

### KubernetesRA

Implementation of the `CertificateAuthority` Interface. If the `EXTERNAL_CA` is set to `ISTIO_RA_KUBERNETES_API` on install, a `KubernetesRA` will be initialized as the internal represenation of a RA which integrates with an external CA using the Kubernetes CSR API.

```go
// KubernetesRA integrated with an external CA using Kubernetes CSR API
type KubernetesRA struct {
    csrInterface                 clientset.Interface
    keyCertBundle                *util.KeyCertBundle
    raOpts                       *IstioRAOptions
    caCertificatesFromMeshConfig map[string]string
    certSignerDomain             string
    // mutex protects the R/W to caCertificatesFromMeshConfig.
    mutex sync.RWMutex
}
```

### IstioCA

Implementation of the `CertificateAuthority` Interface. If a external or custom CA is not specified on install, a `IstioCA` will be initilized as the internal representation of the CA. In this scenario, Istiod functions as the CA and RA and makes no external CA calls.

```go
// IstioCA generates keys and certificates for Istio identities.
type IstioCA struct {
    defaultCertTTL time.Duration
    maxCertTTL     time.Duration
    caRSAKeySize   int


    keyCertBundle *util.KeyCertBundle


    // rootCertRotator periodically rotates self-signed root cert for CA. It is nil
    // if CA is not self-signed CA.
    rootCertRotator *SelfSignedCARootCertRotator
}
```

## High level CA and RA creation workdflow

![CA and RA creation flow](docs/ca.svg)

- The CA server for Istiod can be disabled using the environment variable `ENABLE_CA_SERVER``. By default the CA server is enabled.
- The `USE_REMOTE_CERTS` environment variable can be set to load CA certs from a config Kubernetes cluster. This is used for an external Istiod. 
- The `EXTERNAL_CA` environment varible specifies the external CA integration type. Supported values are ISTIOD_RA_KUBERNETES_API or ISTIO_RA_ISTIO_API. By default, this value is unset. If unset, there is not RA and all signing requests are accepted. Otherwise, Istio RA signing functionally is initialized. The ca cert used to sign the certificate signing requests can be provided via a Kubernetes secret (mounted at external-ca-cert), the Kubernetes ca cert, or the cert-chain signed by other CSR signers.
- If the RA exists and the PILOT_CERT_PROVIDER is set to kubernetes or begins with "k8s.io/" (signed by external CA) the CA is disabled. The default PILOT_CERT_PROVIDER is Istiod. If the value is kubernetes, the Kubernetes CSR API is used to generate a cert for the control plane. If the value is “k8.io”  the Kubernetes CSR API is used and the specified signer (in the ProxyConfig or MeshConfig).

> Note: More details on the supported environment variables can be found in [Environment Variable](#environment-variables) section.

### Components


Each RA and CA service is registered on the existing Server (different the the server defined above) in the RunCA method.

| Variable | Description | 
| - | - | 
| TOKEN_ISSUER | OIDC token issuer. If set, will be used to check the tokens. Value can also be extracted from a mounted token.<br /><br />If a JWT is mounted in istiod, it is used as the default audience and trust domain for Istiod, if not explicitly defined. K8s automatically injects a token for every pod at a well known location.<br /><br />If an issuer is not set via the env variable the issuer is obtained from the mounted token.<br /><br />Checked when starting the CA/RA service on the istiod server. <br /><br />pilot/pkg/bootstrap/istio_ca.go |
| AUDIENCE | Expected audience in the tokens. If not set and a mounted token is present at a well known location token aud defaults to istio-ca. It is based on the istiod.yaml configuration. Env variable takes precedence over the yaml configuration and default.<br /><br />Checked when starting the CA/RA service on the istiod server. |
| CA_TRUSTED_NODE_ACCOUNTS | If set, the list of service accounts that are allowed to use node authentication for CSRs. Node authentication allows an identity to create CSRs on behalf of other identities, but only if there is a pod running on the same node with that identity. This is intended for use with node proxies.<br /><br /> Results in the creation of NodeAuthorizors to validate node proxy is requesting an ididty of a workload on it’s own node. |



```go
// NodeAuthorizer is a component that implements a subset of Kubernetes Node Authorization
// (https://kubernetes.io/docs/reference/access-authn-authz/node/) for Istio CA. Specifically, it
// validates that a node proxy which requests certificates for workloads on its own node is requesting
// valid identities which run on that node (rather than arbitrary ones).
type NodeAuthorizer struct {
    trustedNodeAccounts map[types.NamespacedName]struct{}
    pods                kclient.Client[*v1.Pod]
    nodeIndex           *kclient.Index[SaNode, *v1.Pod]
}
```

Created when IstioCA 
Istio CSR
Chiron - integrates with kubernetes CSR 
security/pkg/k8s/chiron/utils.go
GenKeyCertK8sCA - generates a key pair and gets public certificate signed by K8s_CA. Options are meant to sign DNS certs.
SignCSRK8s - generates a certificate from CSR using the K8s CA. Submits a CSR, Approves a CSR, reads the signed cert, cleans up artifacts (deletes the CSR)
Approval is automatic. A status condition of certificateApproved is added to the CSR by Chiron
pilot /pkg/bootstrap/certcontroller.go
Calls GenKeyCertK8sCA for generating cert for istiogRPC server and webooks
security/pkg/server/ca/server.go
CA server
CertificateAuthority interface defines Sign() (gnerated a certificate for a workload or CA from given CSR and cert options), SignWithCertChain() (similar to sign but returns the leaf cert and entire cert chain), and GetCAKeyCertBundle returns the KeyCertBundle used by the CA
CreateCertificate handles incoming certificate signing requests (CSR) . It performs authentication and authorization. Upon validation, signs a certificate that the SNA is the identity of the caller in authentication result. The subject public key is the public key in the CSR. The validity duration is the Validity duration in the request or the default value if the given duration is invalid. It is signed by the CA signing key.
Loops over configured authenticators and returns the caller (identity and authentication source of the caller and k8s pod information)
Checks for an impersonated identity
Calls Sign or SignWithCertChain
On kubernetesRA Calls preSign and kubernetesSign
KubernetesSign leverages chiron’s SignCSRK8s which generates a cert from a k8s CSR

### Environment variables

| Variable | Supported Values | Description |
| - | - | - |
| ENABLE_CA_SERVER | true (default), false | If this is set to false, will not create CA server in istiod. |
| USE_REMOTE_CERTS | false (default), true | Whether to try to load CA certs from config Kubernetes cluster. Used for external Istiod. If this is set Istiod will attempt to create the CA server with the loaded CA cert. |
| EXTERNAL_CA | ISTIOD_RA_KUBERNETES_API, ISTIOD_RA_ISTIO_API(This is a no-op for istiod and can be removed), “” (default) | External CA Integration Type. If set, Istiod will configure a RA to make signing requests. By default Istiod will not create a RA.<br /><br /> ISTIOD_RA_KUBERNETES_API specified that Istiod should integrate with an external CA using k8s CSR API.<br /><br /> ISTIOD_RA_ISTIO_API specified that Istiod should integrate with an external CA using the ISTIO CA gRPC API. |
| PILOT_CERT_PROVIDER | "Kubernetes", “k8s.io/”, “custom”, “istiod”, “none”, “” (default) | The provider of the Pilot DNS certificate.<br /><br /> “Kubernetes” specifies the Kubernetes CSR API to generate a DNS certificate for the control plane.<br /><br /> “k8s.io/” specifies the Kubernetes CSR API and the specified signer to generate a DNS certificate for the control plane.<br /><br /> “Custom” specifies the root certificate is mounted in a well known location for the control plane.<br /><br /> “Istiod” specifies the istiod self-signed DNS certificate should be used for fot the control plane.<br /><br />“None” specifies that no certificate should be created from the control plane. It is assumed that some external load balancer, such as an Istiod Gateway, is terminating the TLS. |

