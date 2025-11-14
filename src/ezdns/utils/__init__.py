"""Utility modules for ezdns toolkit."""

from .exceptions import (
    ConfigurationError,
    DNSNoRecordsError,
    DNSQueryError,
    DNSTimeoutError,
    EZDNSError,
    InvalidDomainError,
    IPDetectionError,
    NetworkError,
    WHOISQueryError,
)
from .formatters import (
    CSVFormatter,
    JSONFormatter,
    TextFormatter,
    YAMLFormatter,
    get_formatter,
)
from .validators import (
    is_ipv4,
    is_ipv6,
    is_valid_domain,
    validate_domain,
    validate_domain_with_subdomain,
)

__all__ = [
    # Exceptions
    "EZDNSError",
    "InvalidDomainError",
    "DNSQueryError",
    "DNSTimeoutError",
    "DNSNoRecordsError",
    "WHOISQueryError",
    "IPDetectionError",
    "NetworkError",
    "ConfigurationError",
    # Validators
    "validate_domain",
    "validate_domain_with_subdomain",
    "is_valid_domain",
    "is_ipv4",
    "is_ipv6",
    # Formatters
    "TextFormatter",
    "JSONFormatter",
    "CSVFormatter",
    "YAMLFormatter",
    "get_formatter",
]
