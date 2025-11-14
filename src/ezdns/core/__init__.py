"""Core modules for DNS operations."""

from .dns_resolver import (
    DNSResolver,
    get_a_records,
    get_mx_records,
    get_ns_records,
    get_txt_records,
)
from .ip_detector import IPDetector, get_public_ip
from .whois_lookup import WHOISLookup, get_whois_info, get_whois_nameservers

__all__ = [
    # DNS Resolver
    "DNSResolver",
    "get_a_records",
    "get_mx_records",
    "get_txt_records",
    "get_ns_records",
    # WHOIS Lookup
    "WHOISLookup",
    "get_whois_info",
    "get_whois_nameservers",
    # IP Detector
    "IPDetector",
    "get_public_ip",
]
