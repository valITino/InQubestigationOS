# InQubestigationOS — one entry point for the whole lifecycle.
#
# Everything here is a thin wrapper over the two scripts; nothing is hidden.
# Run `make` on its own to see what each target does.

SHELL := /bin/bash
.DEFAULT_GOAL := help

UID ?= Investigator Image Signing <cyber@example.invalid>
DEVICE ?=

.PHONY: help
help:  ## show this help
	@awk 'BEGIN{FS=":.*##"; printf "\n  \033[1mInQubestigationOS\033[0m\n\n"} \
	     /^[a-z][a-z0-9-]*:.*##/ {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2} \
	     END{print ""}' $(MAKEFILE_LIST)

# --- build host ------------------------------------------------------------
.PHONY: bootstrap
bootstrap:  ## host, key, key backup, checks, plan and build — in that order
	./build_iso.py bootstrap $(if $(UID),--uid "$(UID)",)

.PHONY: host
host:  ## install and configure everything the build host needs
	./build_iso.py setup-host

.PHONY: key
key:  ## create the ISO signing key and record its fingerprint (UID=...)
	./build_iso.py gen-key --uid "$(UID)"

.PHONY: backup-key
backup-key:  ## back up the signing key (TO=/path/on/removable/media)
	./build_iso.py backup-key $(if $(TO),--to $(TO),)

.PHONY: restore-key
restore-key:  ## restore a signing-key backup (FROM=/path)
	./build_iso.py restore-key $(if $(FROM),--from $(FROM),)

.PHONY: doctor
doctor:  ## check the build host is ready, change nothing
	./build_iso.py doctor

.PHONY: upstream
upstream:  ## compare pinned keys and versions against upstream
	./build_iso.py check-upstream

# --- build -----------------------------------------------------------------
.PHONY: plan
plan:  ## print the whole build plan, change nothing
	./build_iso.py --dry-run all

.PHONY: templates
templates:  ## build the five investigator templates
	./build_iso.py templates

.PHONY: iso
iso:  ## build, checksum and sign the ISO
	./build_iso.py iso

.PHONY: all-build
all-build:  ## templates, then the ISO
	./build_iso.py all

.PHONY: usb
usb:  ## verify the ISO and write it to a removable device (DEVICE=/dev/sdX)
	./build_iso.py write-usb $(if $(DEVICE),--device $(DEVICE),)

# --- checks ----------------------------------------------------------------
.PHONY: check
check:  ## run the whole test suite (no Qubes machine needed)
	./tests/run_tests.py

.PHONY: lint
lint:  ## lint all Python code (requires requirements-dev.txt)
	ruff check .

.PHONY: security
security:  ## scan Python for high-severity security defects
	python3 -m bandit -q -lll -r build_iso.py golden_image.py tests

.PHONY: check-docs
check-docs:  ## check the documentation still matches the code
	./tests/doc_checks.py

.PHONY: check-config
check-config:  ## check the code and its configuration agree
	./tests/config_checks.py

.PHONY: check-host
check-host:  ## check the build-host support holds up on the distributions it claims
	./tests/host_checks.py

.PHONY: rotate escrow shred
rotate:  ## (on the laptop) new secrets, applied everywhere
	sudo ./golden_image.py --rotate-credentials
escrow:  ## (on the laptop) copy credentials into the offline vault qube
	sudo ./golden_image.py --escrow-credentials
shred:  ## (on the laptop) destroy the dom0 copy — refuses without an escrow record
	sudo ./golden_image.py --shred-credentials

.PHONY: verify
verify:  ## (on the laptop) run the acceptance tests
	sudo ./golden_image.py --verify

.PHONY: status
status:  ## (on the laptop) phases, credentials, timers, recent results
	sudo ./golden_image.py --status

.PHONY: issue
issue:  ## (on the laptop) verify, then record the release (OPERATOR="Name")
	sudo ./golden_image.py --issue --operator "$(OPERATOR)"

.PHONY: handover
handover:  ## (on the laptop) rotate, escrow and shred, in that order
	sudo ./golden_image.py --handover

.PHONY: backup-media
backup-media:  ## (on the laptop) partition, format and label the backup disk
	sudo ./golden_image.py --prepare-backup-media

.PHONY: ci
ci:  ## run every portable CI check locally (live Fedora runs in GitHub Actions)
	python3 -m py_compile golden_image.py build_iso.py
	ruff check .
	python3 -m bandit -q -lll -r build_iso.py golden_image.py tests
	./tests/run_tests.py
	./tests/host_checks.py
	./tests/config_checks.py
	./tests/doc_checks.py
	./build_iso.py check-upstream

.PHONY: clean
clean:  ## remove local build state and caches
	rm -rf __pycache__ tests/__pycache__ .pytest_cache
