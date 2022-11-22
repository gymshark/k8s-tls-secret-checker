package writer

import "github.com/gymshark/k8s-secret-cert-checker/internal/checker"

type Writer interface {
	Write()
	SetItems(items map[string][]checker.SecretAndCert)
}
