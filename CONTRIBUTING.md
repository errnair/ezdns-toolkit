# Contributing

## Development Setup

```bash
git clone https://github.com/errnair/ezdns-toolkit.git
cd ezdns-toolkit
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
pytest --cov=ezdns
pytest tests/unit/test_validators.py  # specific file
```

## Code Style

Use black for formatting, isort for imports:

```bash
black src/ tests/
isort src/ tests/
flake8 src/ tests/
mypy src/
```

Or use the Makefile:

```bash
make format
make lint
make test
```

## Documentation

Use Google-style docstrings for public APIs:

```python
def get_a_records(domain: str) -> List[str]:
    """Query A records for domain."""
```

Only document non-obvious parameters and exceptions.

## Testing

- Add tests for new features
- Maintain or improve code coverage
- Use mocks for external dependencies (DNS, HTTP, WHOIS)

Example:

```python
@patch('dns.resolver.Resolver.resolve')
def test_get_a_records(self, mock_resolve):
    mock_resolve.return_value = [Mock(__str__=Mock(return_value='192.0.2.1'))]
    resolver = DNSResolver()
    records = resolver.get_a_records('example.com')
    assert '192.0.2.1' in records
```

## Pull Requests

1. Fork and create a branch from `master`
2. Make your changes
3. Add tests
4. Run `make check` to verify everything passes
5. Submit PR with clear description

## Bug Reports

Include:
- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Python version)
- Error messages

## License

By contributing, you agree your contributions will be licensed under GPL-3.0.
