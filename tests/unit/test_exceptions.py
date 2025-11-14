"""Unit tests for custom exceptions."""

import pytest
from ezdns.utils.exceptions import (
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


class TestEZDNSError:
    """Base EZDNSError exception."""

    def test_basic_exception(self):
        """Basic exception creation."""
        exc = EZDNSError("Test error")
        assert str(exc) == "Test error"
        assert exc.message == "Test error"

    def test_exception_with_details(self):
        """Exception with details."""
        exc = EZDNSError("Test error", details="Additional info")
        assert exc.message == "Test error"
        assert exc.details == "Additional info"

    def test_exception_inheritance(self):
        """EZDNSError inherits from Exception."""
        exc = EZDNSError("Test")
        assert isinstance(exc, Exception)


class TestInvalidDomainError:
    """InvalidDomainError exception."""

    def test_basic_invalid_domain(self):
        """Basic invalid domain error."""
        exc = InvalidDomainError("invalid..domain")
        assert "invalid..domain" in str(exc)
        assert exc.domain == "invalid..domain"

    def test_invalid_domain_with_reason(self):
        """Invalid domain error with reason."""
        exc = InvalidDomainError("test", reason="Too short")
        assert "test" in str(exc)
        assert "Too short" in str(exc)

    def test_invalid_domain_inheritance(self):
        """InvalidDomainError inherits from EZDNSError."""
        exc = InvalidDomainError("test")
        assert isinstance(exc, EZDNSError)


class TestDNSQueryError:
    """DNSQueryError exception."""

    def test_basic_dns_query_error(self):
        """Basic DNS query error."""
        exc = DNSQueryError("A", "example.com")
        assert "A" in str(exc)
        assert "example.com" in str(exc)
        assert exc.record_type == "A"
        assert exc.domain == "example.com"

    def test_dns_query_error_with_reason(self):
        """DNS query error with reason."""
        exc = DNSQueryError("MX", "example.com", reason="Timeout")
        assert "MX" in str(exc)
        assert "example.com" in str(exc)
        assert "Timeout" in str(exc)

    def test_dns_query_error_inheritance(self):
        """DNSQueryError inherits from EZDNSError."""
        exc = DNSQueryError("A", "example.com")
        assert isinstance(exc, EZDNSError)


class TestDNSTimeoutError:
    """DNSTimeoutError exception."""

    def test_dns_timeout_error(self):
        """DNS timeout error."""
        exc = DNSTimeoutError("A", "example.com")
        assert "A" in str(exc)
        assert "example.com" in str(exc)
        assert "timed out" in str(exc).lower()

    def test_dns_timeout_error_inheritance(self):
        """DNSTimeoutError inherits from DNSQueryError."""
        exc = DNSTimeoutError("A", "example.com")
        assert isinstance(exc, DNSQueryError)
        assert isinstance(exc, EZDNSError)

    def test_timeout_error_attributes(self):
        """Timeout error has correct attributes."""
        exc = DNSTimeoutError("AAAA", "test.com")
        assert exc.record_type == "AAAA"
        assert exc.domain == "test.com"


class TestDNSNoRecordsError:
    """DNSNoRecordsError exception."""

    def test_no_records_error(self):
        """DNS no records error."""
        exc = DNSNoRecordsError("MX", "example.com")
        assert "MX" in str(exc)
        assert "example.com" in str(exc)
        assert "No MX records found" in str(exc)

    def test_no_records_error_inheritance(self):
        """DNSNoRecordsError inherits from DNSQueryError."""
        exc = DNSNoRecordsError("TXT", "example.com")
        assert isinstance(exc, DNSQueryError)
        assert isinstance(exc, EZDNSError)


class TestWHOISQueryError:
    """WHOISQueryError exception."""

    def test_basic_whois_error(self):
        """Basic WHOIS query error."""
        exc = WHOISQueryError("example.com")
        assert "example.com" in str(exc)
        assert exc.domain == "example.com"

    def test_whois_error_with_reason(self):
        """WHOIS error with reason."""
        exc = WHOISQueryError("example.com", reason="Connection failed")
        assert "example.com" in str(exc)
        assert "Connection failed" in str(exc)

    def test_whois_error_inheritance(self):
        """WHOISQueryError inherits from EZDNSError."""
        exc = WHOISQueryError("example.com")
        assert isinstance(exc, EZDNSError)


class TestIPDetectionError:
    """IPDetectionError exception."""

    def test_basic_ip_detection_error(self):
        """Basic IP detection error."""
        exc = IPDetectionError()
        assert "Failed to detect public IP" in str(exc)

    def test_ip_detection_error_with_service(self):
        """IP detection error with service name."""
        exc = IPDetectionError(service="ipify.org")
        assert "ipify.org" in str(exc)
        assert exc.service == "ipify.org"

    def test_ip_detection_error_with_reason(self):
        """IP detection error with reason."""
        exc = IPDetectionError(service="test", reason="Timeout")
        assert "test" in str(exc)
        assert "Timeout" in str(exc)

    def test_ip_detection_error_inheritance(self):
        """IPDetectionError inherits from EZDNSError."""
        exc = IPDetectionError()
        assert isinstance(exc, EZDNSError)


class TestNetworkError:
    """NetworkError exception."""

    def test_basic_network_error(self):
        """Basic network error."""
        exc = NetworkError("DNS query")
        assert "DNS query" in str(exc)
        assert exc.operation == "DNS query"

    def test_network_error_with_reason(self):
        """Network error with reason."""
        exc = NetworkError("HTTP request", reason="Connection refused")
        assert "HTTP request" in str(exc)
        assert "Connection refused" in str(exc)

    def test_network_error_inheritance(self):
        """NetworkError inherits from EZDNSError."""
        exc = NetworkError("operation")
        assert isinstance(exc, EZDNSError)


class TestConfigurationError:
    """ConfigurationError exception."""

    def test_basic_configuration_error(self):
        """Basic configuration error."""
        exc = ConfigurationError("timeout")
        assert "timeout" in str(exc)
        assert exc.parameter == "timeout"

    def test_configuration_error_with_reason(self):
        """Configuration error with reason."""
        exc = ConfigurationError("dns_server", reason="Invalid IP address")
        assert "dns_server" in str(exc)
        assert "Invalid IP address" in str(exc)

    def test_configuration_error_inheritance(self):
        """ConfigurationError inherits from EZDNSError."""
        exc = ConfigurationError("param")
        assert isinstance(exc, EZDNSError)


class TestExceptionUsage:
    """Common exception usage patterns."""

    def test_catching_base_exception(self):
        """All custom exceptions can be caught by base class."""
        exceptions_to_test = [
            InvalidDomainError("test"),
            DNSQueryError("A", "test.com"),
            DNSTimeoutError("A", "test.com"),
            DNSNoRecordsError("A", "test.com"),
            WHOISQueryError("test.com"),
            IPDetectionError(),
            NetworkError("test"),
            ConfigurationError("test"),
        ]

        for exc in exceptions_to_test:
            with pytest.raises(EZDNSError):
                raise exc

    def test_exception_chain(self):
        """Exception chaining."""
        try:
            try:
                raise ValueError("Original error")
            except ValueError as e:
                raise DNSQueryError("A", "example.com", reason=str(e)) from e
        except DNSQueryError as exc:
            assert exc.__cause__ is not None
            assert isinstance(exc.__cause__, ValueError)

    def test_exception_attributes_accessible(self):
        """Custom attributes are accessible."""
        # InvalidDomainError
        exc1 = InvalidDomainError("test.com", reason="Invalid")
        assert exc1.domain == "test.com"
        assert exc1.details == "Invalid"

        # DNSQueryError
        exc2 = DNSQueryError("MX", "test.com", reason="Failed")
        assert exc2.record_type == "MX"
        assert exc2.domain == "test.com"
        assert exc2.details == "Failed"

        # WHOISQueryError
        exc3 = WHOISQueryError("test.com", reason="Timeout")
        assert exc3.domain == "test.com"
        assert exc3.details == "Timeout"

        # IPDetectionError
        exc4 = IPDetectionError(service="ipify", reason="Failed")
        assert exc4.service == "ipify"
        assert exc4.details == "Failed"

        # NetworkError
        exc5 = NetworkError("request", reason="Timeout")
        assert exc5.operation == "request"
        assert exc5.details == "Timeout"

        # ConfigurationError
        exc6 = ConfigurationError("param", reason="Invalid")
        assert exc6.parameter == "param"
        assert exc6.details == "Invalid"

    def test_exception_string_representations(self):
        """All exceptions have meaningful string representations."""
        exceptions = [
            InvalidDomainError("test", reason="Invalid"),
            DNSQueryError("A", "test.com", reason="Failed"),
            DNSTimeoutError("A", "test.com"),
            DNSNoRecordsError("MX", "test.com"),
            WHOISQueryError("test.com", reason="Failed"),
            IPDetectionError(service="test", reason="Failed"),
            NetworkError("operation", reason="Failed"),
            ConfigurationError("param", reason="Invalid"),
        ]

        for exc in exceptions:
            # Each exception should have a non-empty string representation
            exc_str = str(exc)
            assert exc_str
            assert len(exc_str) > 0
            # Should contain the error message
            assert exc.message in exc_str
