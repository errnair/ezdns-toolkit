"""Utility modules for ezdns toolkit."""

from .exceptions import (
    EZDNSError,
    InvalidDomainError,
    DNSQueryError,
    DNSTimeoutError,
    DNSNoRecordsError,
    WHOISQueryError,
    IPDetectionError,
    NetworkError,
    ConfigurationError,
)
from .validators import (
    validate_domain,
    validate_domain_with_subdomain,
    is_valid_domain,
    is_ipv4,
    is_ipv6,
)
from .formatters import (
    TextFormatter,
    JSONFormatter,
    CSVFormatter,
    YAMLFormatter,
    get_formatter,
)

__all__ = [
    # Exceptions
    'EZDNSError',
    'InvalidDomainError',
    'DNSQueryError',
    'DNSTimeoutError',
    'DNSNoRecordsError',
    'WHOISQueryError',
    'IPDetectionError',
    'NetworkError',
    'ConfigurationError',
    # Validators
    'validate_domain',
    'validate_domain_with_subdomain',
    'is_valid_domain',
    'is_ipv4',
    'is_ipv6',
    # Formatters
    'TextFormatter',
    'JSONFormatter',
    'CSVFormatter',
    'YAMLFormatter',
    'get_formatter',
]
