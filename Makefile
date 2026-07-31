# chainsentry developer Makefile
#
# Common dev tasks. Designed for humans + CI.
# Run `make` for the help menu.

.PHONY: help test scan demo clean lint

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

test: ## Run the test suite.
	python3 -m pytest tests/ -v

scan: ## Run chainsentry against the bundled vulnerable.sol fixture.
	python3 -m chainsentry contracts/vulnerable.sol -f text

scan-md: ## Markdown report into report.md
	python3 -m chainsentry contracts/vulnerable.sol -f markdown -o report.md

scan-json: ## JSON report into report.json
	python3 -m chainsentry contracts/vulnerable.sol -f json -o report.json

scan-ci: ## CI gate: fail if any high or critical finding.
	python3 -m chainsentry contracts/vulnerable.sol --fail-on high

demo: ## Scan + show the first 5 findings.
	@python3 -m chainsentry contracts/vulnerable.sol -f text | head -10

list-detectors: ## List all detectors and their severity.
	python3 -m chainsentry --list-detectors

web: ## Run the Flask web UI on http://127.0.0.1:5000
	python3 -m web.app

clean: ## Remove generated reports.
	rm -f report.md report.json

lint: ## Sanity-check Python syntax.
	@python3 -m py_compile chainsentry/scanner.py chainsentry/cli.py chainsentry/models.py chainsentry/reporters.py
	@find chainsentry/detectors -name '*.py' -exec python3 -m py_compile {} +
	@echo "All Python files compile OK."
