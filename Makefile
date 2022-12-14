EXECUTABLE=k8s-check-certs
WINDOWS=./bin/$(EXECUTABLE)_windows_amd64.exe
LINUX=./bin/$(EXECUTABLE)_linux_amd64
DARWIN=./bin/$(EXECUTABLE)_darwin_amd64
M1=./bin/$(EXECUTABLE)_darwin_arm64
VERSION=$(shell git describe --tags --always --long --dirty)

.PHONY: clean

build: windows linux darwin m1 ## Build binaries
	@echo version: $(VERSION)

windows: $(WINDOWS) ## Build for Windows

linux: $(LINUX) ## Build for Linux

darwin: $(DARWIN) ## Build for Darwin (macOS)

m1: $(M1)

$(WINDOWS):
	env GOOS=windows GOARCH=amd64 go build -v -o $(WINDOWS) -ldflags="-s -w -X main.version=$(VERSION)"  ./cmd/k8s-check-certs/main.go

$(LINUX):
	env GOOS=linux GOARCH=amd64 go build -v -o $(LINUX) -ldflags="-s -w -X main.version=$(VERSION)"  ./cmd/k8s-check-certs/main.go

$(DARWIN):
	env GOOS=darwin GOARCH=amd64 go build -v -o $(DARWIN) -ldflags="-s -w -X main.version=$(VERSION)"  ./cmd/k8s-check-certs/main.go

$(M1):
	env GOOS=darwin GOARCH=arm64 go build -v -o $(M1) -ldflags="-s -w -X main.version=$(VERSION)"  ./cmd/k8s-check-certs/main.go

clean: ## Remove previous build
	rm -f $(WINDOWS) $(LINUX) $(DARWIN) $(M1)

help: ## Display available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'