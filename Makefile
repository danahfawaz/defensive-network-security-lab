# Convenience targets. Everything is plain Python 3.11+ (standard library + PyYAML); no network access is needed.
# The date is pinned so that waiver expiry, and therefore the committed evidence, is reproducible.
PY      ?= python3
TODAY   ?= 2026-10-12
export PYTHONPATH := src
CA      := $(PY) -m ciscoaudit

.PHONY: all test audit design validate matrix docs-check evidence evidence-check check-secrets rules clean

all: test audit design validate matrix docs-check evidence-check check-secrets

test:            ## unit tests
	$(PY) -m unittest discover -s tests -t .

audit:           ## audit the hardened configs with the committed waivers; fails on any open finding
	$(CA) audit configs/hardened --waivers waivers/hardened.yaml --today $(TODAY) --fail-on info

design:          ## topology and configs agree with each other
	$(CA) design-check --state all

validate:        ## 124 scenarios against the hardened configs (simulation)
	$(CA) validate --state hardened

matrix:          ## every sender x destination x service against the written policy
	$(CA) matrix --state hardened

docs-check:       ## generated tables are up to date
	$(PY) scripts/generate_docs.py --check

evidence:        ## regenerate evidence/ (audit, validation, matrix, unit-test summary)
	$(PY) scripts/make_evidence.py

evidence-check:  ## committed evidence matches what the tools produce
	$(PY) scripts/make_evidence.py --check --skip-tests

check-secrets:   ## committed configs hold placeholders only
	$(PY) scripts/render_configs.py --check

rules:           ## rule catalogue
	$(CA) rules --format markdown

clean:
	rm -rf build .pytest_cache; find . -name __pycache__ -type d -prune -exec rm -rf {} +
