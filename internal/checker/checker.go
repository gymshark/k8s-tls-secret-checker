package checker

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"math"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Checker struct {
	k8s        *kubernetes.Clientset
	k8sDynamic dynamic.Interface
}

type Option func(*Checker)

func WithK8sClientSet(clientSet *kubernetes.Clientset) Option {
	return func(c *Checker) {
		c.k8s = clientSet
	}
}

func WithK8sDynamicClient(dynamicClient *dynamic.Interface) Option {
	return func(c *Checker) {
		c.k8sDynamic = *dynamicClient
	}
}

type SecretAndCert struct {
	Secret           v1.Secret        `json:"-"`
	Cert             x509.Certificate `json:"-"`
	SecretName       string           `json:"secretName"`
	CertManager      CertManagerData  `json:"certManager"`
	Expired          bool             `json:"expired"`
	DaysUntilExpired float64          `json:"timeUntilExpired"`
}

type CertManagerData struct {
	CertificateName           string `json:"certificateName"`
	CertificateResourceExists bool   `json:"certificateResourceExists"`
	StatusMessage             string `json:"statusMessage"`
	Status                    string `json:"status"`
	DanglingResource          bool   `json:"danglingResource"`
	DanglingResourceName      string `json:"danglingResourceName"`
}

func NewChecker(opts ...Option) *Checker {
	checker := &Checker{}

	for _, opt := range opts {
		opt(checker)
	}

	if checker.k8s == nil {
		panic(fmt.Errorf("checker: option `WithK8sClientSet` must be passed to NewChecker"))
	}

	return checker
}

func (c *Checker) GetProblemTlsSecrets(namespace *string) (map[string][]SecretAndCert, error) {
	secrets, err := c.k8s.CoreV1().Secrets(*namespace).List(context.TODO(), metav1.ListOptions{
		FieldSelector: "type=kubernetes.io/tls",
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching secrets for namespace: %s %s", namespace, err)
	}

	problemSecrets := map[string][]SecretAndCert{}

	for _, secret := range secrets.Items {
		certString := secret.Data["tls.crt"]
		block, _ := pem.Decode(certString)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %s/%s %s", secret.Namespace, secret.Name, err)
		}
		if len(cert.DNSNames) == 0 {
			continue
		}

		if time.Until(cert.NotAfter) < 0 || cert.NotAfter.Sub(time.Now()).Hours()/24 < 30 {
			secretAndCert := SecretAndCert{
				Cert:             *cert,
				Secret:           secret,
				SecretName:       secret.Name,
				Expired:          cert.NotAfter.Sub(time.Now()).Hours()/24 < 0,
				DaysUntilExpired: math.Round(cert.NotAfter.Sub(time.Now()).Hours() / 24),
			}

			if certName, ok := secret.Annotations["cert-manager.io/certificate-name"]; ok {
				secretAndCert.CertManager.CertificateName = certName

				gvr := schema.GroupVersionResource{
					Group:    "cert-manager.io",
					Version:  "v1",
					Resource: "certificates",
				}

				certManagerCertificateResult, err := c.k8sDynamic.Resource(gvr).Namespace(secret.Namespace).Get(context.TODO(), certName, metav1.GetOptions{})
				if err != nil {
					secretAndCert.CertManager.CertificateResourceExists = false
				} else {
					secretAndCert.CertManager.CertificateResourceExists = true
					secretAndCert.CertManager.Status = certManagerCertificateResult.Object["status"].(map[string]interface{})["conditions"].([]interface{})[0].(map[string]interface{})["reason"].(string)
					secretAndCert.CertManager.StatusMessage = certManagerCertificateResult.Object["status"].(map[string]interface{})["conditions"].([]interface{})[0].(map[string]interface{})["message"].(string)
					secretAndCert.CertManager.DanglingResource = certManagerCertificateResult.Object["spec"].(map[string]interface{})["secretName"].(string) != secret.Name
					secretAndCert.CertManager.DanglingResourceName = certManagerCertificateResult.Object["spec"].(map[string]interface{})["secretName"].(string)
				}
			}

			if _, ok := problemSecrets[secret.Namespace]; !ok {
				problemSecrets[secret.Namespace] = []SecretAndCert{}
			}

			problemSecrets[secret.Namespace] = append(problemSecrets[secret.Namespace], secretAndCert)
		}
	}

	return problemSecrets, nil
}
