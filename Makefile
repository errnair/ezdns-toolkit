.PHONY: help install install-dev test test-coverage test-verbose lint format clean build publish docs

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest
BLACK := $(PYTHON) -m black
ISORT := $(PYTHON) -m isort
FLAKE8 := $(PYTHON) -m flake8
MYPY := $(PYTHON) -m mypy
BANDIT := $(PYTHON) -m bandit

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install package in production mode
	$(PIP) install -e .

install-dev: ## Install package with development dependencies
	$(PIP) install -e ".[dev]"
	@echo "Development environment ready!"

test: ## Run all tests
	$(PYTEST)

test-unit: ## Run unit tests only
	$(PYTEST) tests/unit/

test-integration: ## Run integration tests only
	$(PYTEST) tests/integration/

test-coverage: ## Run tests with coverage report
	$(PYTEST) --cov=ezdns --cov-report=html --cov-report=term-missing
	@echo "Coverage report generated in htmlcov/index.html"

test-verbose: ## Run tests with verbose output
	$(PYTEST) -v

test-fast: ## Run tests without slow tests
	$(PYTEST) -k "not slow"

test-watch: ## Run tests in watch mode (requires pytest-watch)
	$(PYTHON) -m pytest_watch

lint: ## Run all linting checks
	@echo "Running flake8..."
	$(FLAKE8) src/ tests/
	@echo "Running mypy..."
	$(MYPY) src/
	@echo "Linting complete!"

lint-fix: ## Run formatters to auto-fix issues
	@echo "Running black..."
	$(BLACK) src/ tests/
	@echo "Running isort..."
	$(ISORT) src/ tests/
	@echo "Formatting complete!"

format: lint-fix ## Alias for lint-fix

security: ## Run security checks
	@echo "Running bandit security scanner..."
	$(BANDIT) -r src/
	@echo "Security scan complete!"

type-check: ## Run type checking with mypy
	$(MYPY) src/

clean: ## Remove build artifacts and cache files
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .tox/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	@echo "Clean complete!"

build: clean ## Build distribution packages
	$(PYTHON) -m build
	@echo "Build complete! Packages in dist/"

build-check: build ## Build and check distribution
	$(PYTHON) -m twine check dist/*

publish-test: build-check ## Publish to Test PyPI
	$(PYTHON) -m twine upload --repository testpypi dist/*

publish: build-check ## Publish to PyPI (production)
	@echo "WARNING: This will publish to production PyPI!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		$(PYTHON) -m twine upload dist/*; \
	fi

docs: ## Generate documentation
	@echo "Generating documentation..."
	@if [ -d "docs/_build" ]; then \
		cd docs && make html; \
	else \
		echo "Sphinx not configured yet"; \
	fi

docs-serve: docs ## Serve documentation locally
	@echo "Serving documentation at http://localhost:8000"
	$(PYTHON) -m http.server 8000 -d docs/_build/html

check: lint test security ## Run all checks (lint, test, security)
	@echo "All checks passed!"

verify: clean install-dev check ## Full verification (clean, install, check)
	@echo "Verification complete!"

dev: install-dev ## Setup development environment
	@echo "Development environment setup complete!"

run: ## Run the CLI tool
	$(PYTHON) -m ezdns

run-help: ## Show CLI help
	$(PYTHON) -m ezdns --help

run-myip: ## Test: Get public IP
	$(PYTHON) -m ezdns --myip

run-example: ## Run example DNS query
	$(PYTHON) -m ezdns -a example.com

deps-update: ## Update dependencies
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install --upgrade -r requirements.txt
	$(PIP) install --upgrade -r requirements-dev.txt

deps-freeze: ## Freeze current dependencies
	$(PIP) freeze > requirements-frozen.txt
	@echo "Dependencies frozen to requirements-frozen.txt"

init: ## Initialize new development environment
	@echo "Initializing development environment..."
	$(PYTHON) -m venv venv
	@echo "Virtual environment created. Activate with: source venv/bin/activate"
	@echo "Then run: make install-dev"

git-hooks: ## Install git hooks
	@echo "Installing git hooks..."
	@echo "#!/bin/bash\nmake lint test" > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Git hooks installed!"

release-patch: ## Create a patch release (0.0.X)
	@echo "Creating patch release..."
	@read -p "Commit message: " msg; \
	git add .; \
	git commit -m "$$msg"; \
	git push

release-minor: ## Create a minor release (0.X.0)
	@echo "Creating minor release..."
	@echo "Update version in src/ezdns/config/settings.py first!"

release-major: ## Create a major release (X.0.0)
	@echo "Creating major release..."
	@echo "Update version in src/ezdns/config/settings.py first!"

info: ## Show project information
	@echo "Project: ezdns-toolkit"
	@echo "Python: $$($(PYTHON) --version)"
	@echo "Location: $$(pwd)"
	@echo "Package installed: $$($(PIP) show ezdns-toolkit | grep Location || echo 'Not installed')"

tree: ## Show project directory tree
	@tree -I 'venv|__pycache__|*.pyc|.git|.mypy_cache|.pytest_cache|htmlcov|*.egg-info|dist|build' -L 3

stats: ## Show code statistics
	@echo "Code Statistics:"
	@echo "----------------"
	@echo "Python files: $$(find src/ -name '*.py' | wc -l)"
	@echo "Test files: $$(find tests/ -name '*.py' | wc -l)"
	@echo "Total lines of code:"
	@find src/ -name '*.py' -exec wc -l {} + | tail -1
	@echo "Total lines of tests:"
	@find tests/ -name '*.py' -exec wc -l {} + | tail -1

upgrade-pip: ## Upgrade pip and build tools
	$(PIP) install --upgrade pip setuptools wheel build twine

.PHONY: all
all: clean install-dev lint test ## Run clean, install, lint, and test
