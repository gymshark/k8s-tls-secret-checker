# K8s Secret Cert Checker

A simple tool to check any tls certs against the following criteria:

- Checks for expired or soon to be expiring certs
- Checks for cert-manager managed certs
  - Checks for dangling resources that were managed by cert-manager but may not be anymore
  - Checks for cert-manager certs that have changed secret targets, leaving resources left over

## Installation

Just download one of the binaries from the releases page.

## Usage

By default, the command will query all available namespaces in your current kube context.

You can change this by using the `--namespace` flag.

```shell
./k8s-check-certs
```