"""DNS query operations using dnspython."""

import logging
from typing import Dict, List, Optional

import dns.exception
import dns.resolver

from ..config.settings import settings
from ..utils.exceptions import (
    DNSNoRecordsError,
    DNSQueryError,
    DNSTimeoutError,
)
from ..utils.validators import validate_domain

logger = logging.getLogger(__name__)


class DNSResolver:
    """DNS query resolver with error handling and retry logic."""

    def __init__(
        self, timeout: float = None, lifetime: float = None, nameservers: Optional[List[str]] = None
    ):
        """Initialize DNS resolver.

        Args:
            timeout: Query timeout in seconds
            lifetime: Total query lifetime in seconds
            nameservers: List of nameserver IPs (uses system default if None)
        """
        self.resolver = dns.resolver.Resolver()

        if timeout:
            self.resolver.timeout = timeout
        else:
            self.resolver.timeout = settings.DNS_TIMEOUT

        if lifetime:
            self.resolver.lifetime = lifetime
        else:
            self.resolver.lifetime = settings.DNS_LIFETIME

        if nameservers:
            self.resolver.nameservers = nameservers
        elif settings.DNS_NAMESERVERS:
            self.resolver.nameservers = settings.DNS_NAMESERVERS

        logger.debug(
            f"DNS Resolver initialized: timeout={self.resolver.timeout}s, "
            f"lifetime={self.resolver.lifetime}s"
        )

    def _query(self, domain: str, record_type: str) -> List[str]:
        """Perform DNS query."""
        try:
            logger.debug(f"Querying {record_type} records for {domain}")
            answers = self.resolver.resolve(domain, record_type)

            results = []
            for rdata in answers:
                results.append(str(rdata))

            logger.info(f"Found {len(results)} {record_type} record(s) for {domain}")
            return results

        except dns.resolver.Timeout:
            logger.warning(f"DNS query timeout for {domain} ({record_type})")
            # Try fallback with public DNS servers for certain record types
            if record_type in ["NS", "SOA"] and not hasattr(self, "_tried_fallback"):
                logger.info(f"Attempting fallback query with public DNS servers")
                return self._query_with_fallback(domain, record_type)
            raise DNSTimeoutError(record_type, domain)

        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain does not exist: {domain}")
            raise DNSQueryError(record_type, domain, "Domain does not exist (NXDOMAIN)")

        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records found for {domain}")
            raise DNSNoRecordsError(record_type, domain)

        except dns.resolver.NoNameservers:
            logger.error(f"No nameservers available for {domain}")
            # Try fallback with public DNS servers for certain record types
            if record_type in ["NS", "SOA"] and not hasattr(self, "_tried_fallback"):
                logger.info(f"Attempting fallback query with public DNS servers")
                return self._query_with_fallback(domain, record_type)
            raise DNSQueryError(record_type, domain, "No nameservers responded")

        except dns.exception.DNSException as e:
            logger.error(f"DNS exception querying {domain}: {e}")
            raise DNSQueryError(record_type, domain, str(e))

        except Exception as e:
            logger.error(f"Unexpected error querying {domain}: {e}")
            raise DNSQueryError(record_type, domain, f"Unexpected error: {e}")

    def _query_with_fallback(self, domain: str, record_type: str) -> List[str]:
        """Perform DNS query with fallback to public DNS servers."""
        fallback_nameservers = [
            ["8.8.8.8", "8.8.4.4"],  # Google Public DNS
            ["1.1.1.1", "1.0.0.1"],  # Cloudflare DNS
            ["208.67.222.222", "208.67.220.220"],  # OpenDNS
        ]

        self._tried_fallback = True

        for nameservers in fallback_nameservers:
            try:
                logger.debug(f"Trying fallback nameservers: {nameservers}")
                fallback_resolver = dns.resolver.Resolver()
                fallback_resolver.nameservers = nameservers
                fallback_resolver.timeout = self.resolver.timeout
                fallback_resolver.lifetime = min(self.resolver.lifetime, 5.0)

                answers = fallback_resolver.resolve(domain, record_type)
                results = [str(rdata) for rdata in answers]

                logger.info(
                    f"Fallback successful: Found {len(results)} {record_type} "
                    f"record(s) for {domain} using {nameservers[0]}"
                )
                delattr(self, "_tried_fallback")
                return results

            except (dns.resolver.Timeout, dns.resolver.NoNameservers):
                logger.debug(f"Fallback with {nameservers[0]} timed out, trying next")
                continue
            except dns.resolver.NXDOMAIN:
                delattr(self, "_tried_fallback")
                raise DNSQueryError(record_type, domain, "Domain does not exist (NXDOMAIN)")
            except dns.resolver.NoAnswer:
                delattr(self, "_tried_fallback")
                raise DNSNoRecordsError(record_type, domain)
            except Exception as e:
                logger.debug(f"Fallback with {nameservers[0]} failed: {e}")
                continue

        # All fallbacks failed
        delattr(self, "_tried_fallback")
        logger.error(f"All fallback nameservers failed for {domain} ({record_type})")
        raise DNSTimeoutError(record_type, domain)

    def get_a_records(self, domain: str) -> List[str]:
        """Query A records for domain."""
        domain = validate_domain(domain)
        return self._query(domain, "A")

    def get_aaaa_records(self, domain: str) -> List[str]:
        """Query AAAA records for domain."""
        domain = validate_domain(domain)
        return self._query(domain, "AAAA")

    def get_mx_records(self, domain: str) -> List[str]:
        """Query MX records for domain."""
        domain = validate_domain(domain)
        return self._query(domain, "MX")

    def get_txt_records(self, domain: str) -> List[str]:
        """Query TXT records for domain."""
        domain = validate_domain(domain)
        return self._query(domain, "TXT")

    def get_ns_records(self, domain: str) -> List[str]:
        """Query NS records for domain."""
        domain = validate_domain(domain)
        return self._query(domain, "NS")

    def get_cname_records(self, domain: str) -> List[str]:
        """Query CNAME records for domain."""
        domain = validate_domain(domain)
        return self._query(domain, "CNAME")

    def get_soa_record(self, domain: str) -> str:
        """Query SOA record for domain."""
        domain = validate_domain(domain)
        results = self._query(domain, "SOA")
        return results[0] if results else None

    def get_caa_records(self, domain: str) -> List[str]:
        """Query CAA records for domain."""
        domain = validate_domain(domain)
        return self._query(domain, "CAA")

    def get_ptr_record(self, ip_address: str) -> List[str]:
        """Query PTR record for IP address."""
        try:
            reverse_name = dns.reversename.from_address(ip_address)
            return self._query(str(reverse_name), "PTR")
        except Exception as e:
            logger.error(f"Error creating reverse name for {ip_address}: {e}")
            raise DNSQueryError("PTR", ip_address, str(e))

    def get_all_records(self, domain: str) -> Dict[str, List[str]]:
        """Query all common DNS records for domain."""
        domain = validate_domain(domain)
        results = {}

        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]

        for record_type in record_types:
            try:
                results[record_type] = self._query(domain, record_type)
            except (DNSNoRecordsError, DNSQueryError) as e:
                logger.debug(f"No {record_type} records for {domain}: {e}")
                results[record_type] = []

        return results


def get_a_records(domain: str, timeout: float = None) -> List[str]:
    """Get A records."""
    resolver = DNSResolver(timeout=timeout)
    return resolver.get_a_records(domain)


def get_mx_records(domain: str, timeout: float = None) -> List[str]:
    """Get MX records."""
    resolver = DNSResolver(timeout=timeout)
    return resolver.get_mx_records(domain)


def get_txt_records(domain: str, timeout: float = None) -> List[str]:
    """Get TXT records."""
    resolver = DNSResolver(timeout=timeout)
    return resolver.get_txt_records(domain)


def get_ns_records(domain: str, timeout: float = None) -> List[str]:
    """Get NS records."""
    resolver = DNSResolver(timeout=timeout)
    return resolver.get_ns_records(domain)
