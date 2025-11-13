# Test Suite

200+ tests covering DNS, WHOIS, validators, formatters, and CLI.

## Structure

```
tests/
├── conftest.py
├── unit/
│   ├── test_validators.py
│   ├── test_dns_resolver.py
│   ├── test_whois_lookup.py
│   ├── test_ip_detector.py
│   ├── test_formatters.py
│   └── test_exceptions.py
└── integration/
    └── test_cli.py
```

## Running Tests

```bash
pytest                                  # All tests
pytest tests/unit/test_validators.py    # Specific file
pytest -v                               # Verbose
pytest --cov=ezdns --cov-report=html    # With coverage
pytest -k timeout                       # Match pattern
```

## Coverage

Unit tests cover validators, DNS resolver, WHOIS lookup, IP detection, formatters, and exceptions. Integration tests verify CLI functionality. Target >80% overall coverage.

## Fixtures

See `conftest.py` for shared test fixtures including mock resolvers, sample domains, and response data.

## Debugging

```bash
pytest --lf     # Run last failed
pytest --pdb    # Drop into debugger on failure
pytest -l       # Show local variables
```
