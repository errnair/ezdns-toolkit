# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Minimum Python version raised from 3.8 to 3.9
- Python 3.8 reached end-of-life in October 2024

### Removed
- Dropped Python 3.8 support due to dependency compatibility issues

## [2.0.0] - 2025-01-08

### Added
- Restructured to src-layout
- RFC 1035 input validation
- HTTPS IP detection with fallback
- IPv6 (AAAA) support
- CNAME, SOA, CAA, PTR record types
- Reverse DNS lookup
- JSON, CSV, YAML output formats
- WHOIS information extraction
- Configurable logging
- Custom exception classes
- Test suite with pytest
- Type hints
- pyproject.toml packaging (PEP 518)
- Automatic fallback to public DNS servers (Google, Cloudflare, OpenDNS) for NS and SOA queries when local DNS fails

### Changed
- Use `dns.resolver.resolve()` instead of deprecated `query()`
- Updated dependencies to latest versions
- Switched to HTTPS for IP detection
- Improved error messages
- Enhanced nameserver comparison output

### Security
- Fixed HTTP vulnerability
- Input sanitization against injection
- Null-byte and control character filtering
- SSL certificate verification
- Removed wildcard imports

### Deprecated
- Old `main.py` entry point (use `ezdns` command or `python -m ezdns`)

### Removed
- wtfismyip.com dependency
- pkg-resources dependency
- tldextract 2.x (upgraded to 5.x)

## [1.0.0] - 2017-XX-XX

### Added
- Initial release
- Basic DNS record lookup (A, MX, TXT, NS)
- WHOIS nameserver query
- Public IP detection
- Text output format
