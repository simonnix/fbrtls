PROJECT_NAME = fbrtls

.PHONY: all
all: build

## Location to install build
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Location of config dir
CONFDIR ?= $(shell pwd)/config
$(CONFDIR):
	mkdir -p $(CONFDIR)

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test: fmt vet

export PKI_DIR = $(shell pwd)/test_pki
export EZTESTPKI_VARS = $(CONFDIR)/eztestpki.vars
EZTESTPKI_DIR ?= $(shell pwd)/tools/eztestpki

.PHONY: envtest
envtest: $(CONFDIR)
	$(EZTESTPKI_DIR)/easytestpki.sh
	scripts/mkconfig.sh > $(CONFDIR)/$(PROJECT_NAME).yaml

.PHONY: build
build: $(LOCALBIN) test envtest
	go build -o $(LOCALBIN)/$(PROJECT_NAME) main.go
