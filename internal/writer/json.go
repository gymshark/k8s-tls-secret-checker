package writer

import (
	"encoding/json"
	"fmt"
	"github.com/gymshark/k8s-secret-cert-checker/internal/checker"
)

type JSONWriter struct {
	items map[string][]checker.SecretAndCert
}

func NewJSONWriter() Writer {
	return &JSONWriter{}
}

func (w *JSONWriter) SetItems(items map[string][]checker.SecretAndCert) {
	w.items = items
}

func (w *JSONWriter) Write() {
	json, err := json.Marshal(w.items)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(json))
}
