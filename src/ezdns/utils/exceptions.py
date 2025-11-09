"""Custom exception classes."""


class EZDNSError(Exception):
    """Base exception class for all ezdns errors."""

    def __init__(self, message: str, details: str = None):
        self.message = message
        self.details = details
        super().__init__(self.message)


class InvalidDomainError(EZDNSError):
    """Raised when an invalid domain name is provided."""

    def __init__(self, domain: str, reason: str = None):
        message = f"Invalid domain name: {domain}"
        if reason:
            message += f" - {reason}"
        super().__init__(message, details=reason)
        self.domain = domain


class DNSQueryError(EZDNSError):
    """Raised when a DNS query fails."""

    def __init__(self, record_type: str, domain: str, reason: str = None):
        message = f"Failed to query {record_type} records for {domain}"
        if reason:
            message += f": {reason}"
        super().__init__(message, details=reason)
        self.record_type = record_type
        self.domain = domain


class DNSTimeoutError(DNSQueryError):
    """Raised when a DNS query times out."""

    def __init__(self, record_type: str, domain: str):
        reason = "Query timed out - DNS server did not respond"
        super().__init__(record_type, domain, reason)


class DNSNoRecordsError(DNSQueryError):
    """Raised when no DNS records are found."""

    def __init__(self, record_type: str, domain: str):
        reason = f"No {record_type} records found"
        super().__init__(record_type, domain, reason)


class WHOISQueryError(EZDNSError):
    """Raised when a WHOIS query fails."""

    def __init__(self, domain: str, reason: str = None):
        message = f"Failed to query WHOIS information for {domain}"
        if reason:
            message += f": {reason}"
        super().__init__(message, details=reason)
        self.domain = domain


class IPDetectionError(EZDNSError):
    """Raised when public IP detection fails."""

    def __init__(self, service: str = None, reason: str = None):
        message = "Failed to detect public IP address"
        if service:
            message += f" using {service}"
        if reason:
            message += f": {reason}"
        super().__init__(message, details=reason)
        self.service = service


class NetworkError(EZDNSError):
    """Raised when a network operation fails."""

    def __init__(self, operation: str, reason: str = None):
        message = f"Network error during {operation}"
        if reason:
            message += f": {reason}"
        super().__init__(message, details=reason)
        self.operation = operation


class ConfigurationError(EZDNSError):
    """Raised when there's a configuration problem."""

    def __init__(self, parameter: str, reason: str = None):
        message = f"Configuration error for {parameter}"
        if reason:
            message += f": {reason}"
        super().__init__(message, details=reason)
        self.parameter = parameter
