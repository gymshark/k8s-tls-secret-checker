package main

import (
	"flag"
	"fmt"
	"github.com/gymshark/k8s-secret-cert-checker/internal/checker"
	"github.com/gymshark/k8s-secret-cert-checker/internal/writer"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
)

func main() {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	namespace := flag.String("namespace", "", "(optional) the namespace to query, will search all namespaces by default")
	output := flag.String("output", "text", "(optional) the output type, valid options are text or json, default is text")
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	dynamicClient := dynamic.NewForConfigOrDie(config)

	checkClient := checker.NewChecker(
		checker.WithK8sClientSet(clientset),
		checker.WithK8sDynamicClient(&dynamicClient),
	)

	var outputWriter writer.Writer
	switch *output {
	case "text":
		outputWriter = writer.NewTextWriter()
	case "json":
		outputWriter = writer.NewJSONWriter()
	default:
		panic(fmt.Errorf("output option %s not valid", *output))
	}

	problemSecrets, err := checkClient.GetProblemTlsSecrets(namespace)
	if err != nil {
		panic(err)
	}

	outputWriter.SetItems(problemSecrets)
	outputWriter.Write()
}
