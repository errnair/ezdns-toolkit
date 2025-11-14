"""ezdns - DNS lookup and domain information toolkit.

A modern, secure DNS investigation tool for network administrators,
developers, and security professionals.

Usage:
    from ezdns import DNSResolver, get_public_ip

    # Query DNS records
    resolver = DNSResolver()
    a_records = resolver.get_a_records('example.com')

    # Get public IP
    my_ip = get_public_ip()

Command-line usage:
    ezdns --help
    ezdns -a example.com
    ezdns --myip
"""

from .config import settings
from .core import (
    DNSResolver,
    WHOISLookup,
    IPDetector,
    get_a_records,
    get_mx_records,
    get_txt_records,
    get_ns_records,
    get_whois_info,
    get_whois_nameservers,
    get_public_ip,
)
from .utils import (
    EZDNSError,
    InvalidDomainError,
    DNSQueryError,
    DNSTimeoutError,
    DNSNoRecordsError,
    WHOISQueryError,
    IPDetectionError,
    validate_domain,
    is_valid_domain,
)

__version__ = settings.VERSION
__author__ = 'Rahul Nair'
__license__ = 'GPL-3.0'
__all__ = [
    # Version
    '__version__',
    # Core classes
    'DNSResolver',
    'WHOISLookup',
    'IPDetector',
    # Convenience functions
    'get_a_records',
    'get_mx_records',
    'get_txt_records',
    'get_ns_records',
    'get_whois_info',
    'get_whois_nameservers',
    'get_public_ip',
    # Exceptions
    'EZDNSError',
    'InvalidDomainError',
    'DNSQueryError',
    'DNSTimeoutError',
    'DNSNoRecordsError',
    'WHOISQueryError',
    'IPDetectionError',
    # Validators
    'validate_domain',
    'is_valid_domain',
]
