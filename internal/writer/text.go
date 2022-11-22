package writer

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/gymshark/k8s-secret-cert-checker/internal/checker"
	"time"
)

type TextWriter struct {
	items map[string][]checker.SecretAndCert
}

func NewTextWriter() Writer {
	return &TextWriter{}
}

func (w *TextWriter) SetItems(items map[string][]checker.SecretAndCert) {
	w.items = items
}

func (w *TextWriter) Write() {
	for namespace, secrets := range w.items {
		color.Green("\nNamespace: %s\n\n", namespace)

		for _, secret := range secrets {
			color.Cyan("\tSecret: %s\n", secret.Secret.Name)
			fmt.Printf("\tSubject: %s\n", secret.Cert.Subject)
			fmt.Printf("\tDNS Names: \n")
			for _, dnsName := range secret.Cert.DNSNames {
				fmt.Printf("\t\t%s\n", dnsName)
			}
			timeRemaining := fmt.Sprintf("%f", secret.Cert.NotAfter.Sub(time.Now()).Hours()/24)
			if secret.Cert.NotAfter.Sub(time.Now()).Hours()/24 < 30 {
				timeRemaining = color.RedString("%f", secret.Cert.NotAfter.Sub(time.Now()).Hours()/24)
			} else if secret.Cert.NotAfter.Sub(time.Now()).Hours()/24 < 15 {
				timeRemaining = color.YellowString("%f", secret.Cert.NotAfter.Sub(time.Now()).Hours()/24)
			}
			fmt.Printf("\tDays Until Expiry: %s\n", timeRemaining)
			fmt.Printf("\tExpiry Date: %s\n", secret.Cert.NotAfter)

			if certName, ok := secret.Secret.Annotations["cert-manager.io/certificate-name"]; ok {
				fmt.Printf("\tManaged By Certificate Resource: %s/%s\n", secret.Secret.Namespace, certName)

				if !secret.CertManager.CertificateResourceExists {
					color.Red("\t\t!!!CERTIFICATE RESOURCE DOES NOT EXIST!!!\n")
					color.Yellow("\t\tIf this is left, and is un use, any domain it is being used for will have an expired certificate.\n")
					color.Yellow("\t\tIf this is not in use, it may cause issues for any new certificates created for the same domain in the future.\n")
				} else {
					if secret.CertManager.DanglingResource {
						color.Yellow("\t\tThis resource was managed by Cert Manager, but the original Certificate resource is now set to point to another secret.\n")
						color.Yellow("\t\tAll references to this secret should be replaced, and instead reference \"%s\". \n", secret.CertManager.DanglingResourceName)
						color.Yellow("\t\tOnce  done, this resource should be deleted.\n")
					} else {
						fmt.Printf("\t\tCert Manager Status: %s\n", secret.CertManager.Status)
						fmt.Printf("\t\tCert Manager Message: %s\n", secret.CertManager.StatusMessage)
					}
				}
			}
			fmt.Println("")
		}

		fmt.Println("")
	}
}
