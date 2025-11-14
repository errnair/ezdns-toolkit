"""Unit tests for IP detector module."""

import json
import urllib.error
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest

from ezdns.core.ip_detector import IPDetector, get_public_ip
from ezdns.utils.exceptions import IPDetectionError


class TestIPDetector:
    """IPDetector class."""

    def test_initialization_default(self):
        """IPDetector initializes with default settings."""
        detector = IPDetector()
        assert detector.timeout > 0
        assert len(detector.services) > 0

    def test_initialization_custom_timeout(self):
        """IPDetector accepts custom timeout."""
        detector = IPDetector(timeout=15.0)
        assert detector.timeout == 15.0

    @patch("urllib.request.urlopen")
    def test_detect_ip_success_json(self, mock_urlopen):
        """Successful IP detection with JSON response."""
        # Setup mock
        mock_response = Mock()
        mock_response.read.return_value = b'{"ip": "203.0.113.42"}'
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        # Execute
        detector = IPDetector()
        ip = detector.detect_ip()

        # Verify
        assert ip == "203.0.113.42"
        mock_urlopen.assert_called_once()

    @patch("urllib.request.urlopen")
    def test_detect_ip_success_plain_text(self, mock_urlopen):
        """Successful IP detection with plain text response."""
        # Setup mock
        mock_response = Mock()
        mock_response.read.return_value = b"203.0.113.42"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        # Execute
        detector = IPDetector()
        ip = detector.detect_ip()

        # Verify
        assert ip == "203.0.113.42"

    @patch("urllib.request.urlopen")
    def test_detect_ip_fallback_to_second_service(self, mock_urlopen):
        """Fallback to second service when first fails."""
        # First call fails, second succeeds
        call_count = 0

        def mock_urlopen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise urllib.error.HTTPError("url", 503, "Service Unavailable", {}, None)
            else:
                mock_response = Mock()
                mock_response.read.return_value = b"203.0.113.42"
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                return mock_response

        mock_urlopen.side_effect = mock_urlopen_side_effect

        # Execute
        detector = IPDetector()
        ip = detector.detect_ip()

        # Verify
        assert ip == "203.0.113.42"
        assert call_count >= 2  # Called at least twice

    @patch("urllib.request.urlopen")
    def test_detect_ip_all_services_fail(self, mock_urlopen):
        """When all IP detection services fail."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "url", 503, "Service Unavailable", {}, None
        )

        detector = IPDetector()
        with pytest.raises(IPDetectionError) as exc_info:
            detector.detect_ip()

        assert "All" in str(exc_info.value) or "failed" in str(exc_info.value)

    @patch("urllib.request.urlopen")
    def test_detect_ip_timeout(self, mock_urlopen):
        """Handling of timeout errors."""
        mock_urlopen.side_effect = TimeoutError("Connection timed out")

        detector = IPDetector()
        with pytest.raises(IPDetectionError):
            detector.detect_ip()

    @patch("urllib.request.urlopen")
    def test_detect_ip_url_error(self, mock_urlopen):
        """Handling of URL errors."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        detector = IPDetector()
        with pytest.raises(IPDetectionError):
            detector.detect_ip()

    @patch("urllib.request.urlopen")
    def test_detect_ip_http_error(self, mock_urlopen):
        """Handling of HTTP errors."""
        mock_urlopen.side_effect = urllib.error.HTTPError("url", 404, "Not Found", {}, None)

        detector = IPDetector()
        with pytest.raises(IPDetectionError):
            detector.detect_ip()

    @patch("urllib.request.urlopen")
    def test_detect_ip_json_with_different_key(self, mock_urlopen):
        """JSON response with different key structure."""
        # Some services might use different JSON keys
        mock_response = Mock()
        mock_response.read.return_value = b'{"YourFuckingIPAddress": "203.0.113.42"}'
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        detector = IPDetector()
        ip = detector.detect_ip()

        assert ip == "203.0.113.42"

    @patch("urllib.request.urlopen")
    def test_detect_ip_invalid_json(self, mock_urlopen):
        """Handling of invalid JSON response."""
        # If JSON is invalid, should try next service
        call_count = 0

        def mock_urlopen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_response = Mock()
            if call_count == 1:
                mock_response.read.return_value = b'{"invalid json'
            else:
                mock_response.read.return_value = b"203.0.113.42"
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            return mock_response

        mock_urlopen.side_effect = mock_urlopen_side_effect

        detector = IPDetector()
        ip = detector.detect_ip()

        # Should fallback to next service and succeed
        assert ip == "203.0.113.42"

    @patch("urllib.request.urlopen")
    def test_detect_ip_empty_response(self, mock_urlopen):
        """Handling of empty response."""
        call_count = 0

        def mock_urlopen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_response = Mock()
            if call_count == 1:
                mock_response.read.return_value = b""
            else:
                mock_response.read.return_value = b"203.0.113.42"
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            return mock_response

        mock_urlopen.side_effect = mock_urlopen_side_effect

        detector = IPDetector()
        ip = detector.detect_ip()

        # Should fallback and succeed
        assert ip == "203.0.113.42"

    @patch("urllib.request.urlopen")
    def test_detect_ip_whitespace_response(self, mock_urlopen):
        """Whitespace is stripped from response."""
        mock_response = Mock()
        mock_response.read.return_value = b"  203.0.113.42\n\n  "
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        detector = IPDetector()
        ip = detector.detect_ip()

        assert ip == "203.0.113.42"

    @patch("urllib.request.Request")
    @patch("urllib.request.urlopen")
    def test_detect_ip_uses_proper_headers(self, mock_urlopen, mock_request):
        """Proper headers are sent with requests."""
        mock_response = Mock()
        mock_response.read.return_value = b"203.0.113.42"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        detector = IPDetector()
        detector.detect_ip()

        # Verify Request was called with headers
        mock_request.assert_called()
        call_kwargs = mock_request.call_args[1]
        assert "headers" in call_kwargs
        headers = call_kwargs["headers"]
        assert "User-Agent" in headers

    @patch("ssl.create_default_context")
    @patch("urllib.request.urlopen")
    def test_detect_ip_uses_ssl_context(self, mock_urlopen, mock_ssl_context):
        """SSL context is created for HTTPS verification."""
        mock_response = Mock()
        mock_response.read.return_value = b"203.0.113.42"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        mock_context = Mock()
        mock_ssl_context.return_value = mock_context

        detector = IPDetector()
        detector.detect_ip()

        # Verify SSL context was created
        mock_ssl_context.assert_called_once()

    @patch("urllib.request.urlopen")
    def test_detect_ip_custom_timeout(self, mock_urlopen):
        """Custom timeout is used."""
        mock_response = Mock()
        mock_response.read.return_value = b"203.0.113.42"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        detector = IPDetector(timeout=20.0)
        detector.detect_ip()

        # Verify timeout was passed to urlopen
        call_kwargs = mock_urlopen.call_args[1]
        assert "timeout" in call_kwargs
        assert call_kwargs["timeout"] == 20.0


class TestConvenienceFunction:
    """Module-level convenience function."""

    @patch("ezdns.core.ip_detector.IPDetector.detect_ip")
    def test_get_public_ip_convenience(self, mock_detect):
        """Convenience function for IP detection."""
        mock_detect.return_value = "203.0.113.42"

        ip = get_public_ip()

        assert ip == "203.0.113.42"
        mock_detect.assert_called_once()

    @patch("ezdns.core.ip_detector.IPDetector.detect_ip")
    def test_get_public_ip_with_timeout(self, mock_detect):
        """Convenience function with custom timeout."""
        mock_detect.return_value = "203.0.113.42"

        ip = get_public_ip(timeout=15.0)

        assert ip == "203.0.113.42"


class TestIPDetectorEdgeCases:
    """Edge cases and error conditions."""

    @patch("urllib.request.urlopen")
    def test_json_response_with_nested_structure(self, mock_urlopen):
        """JSON response with nested data structure."""
        mock_response = Mock()
        # Some services might return nested JSON
        mock_response.read.return_value = b'{"data": {"ip": "203.0.113.42"}}'
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        detector = IPDetector()
        # Should extract first value even if nested
        result = detector._query_service("https://api.example.com/ip")

        # The current implementation takes first value from dict
        assert result is not None

    @patch("urllib.request.urlopen")
    def test_query_service_returns_none_on_error(self, mock_urlopen):
        """_query_service returns None on error."""
        mock_urlopen.side_effect = urllib.error.HTTPError("url", 500, "Error", {}, None)

        detector = IPDetector()
        result = detector._query_service("https://api.example.com/ip")

        assert result is None

    @patch("urllib.request.urlopen")
    def test_multiple_services_configured(self, mock_urlopen):
        """Detector has multiple fallback services."""
        detector = IPDetector()

        # Should have at least 2 services for redundancy
        assert len(detector.services) >= 2

        # All services should use HTTPS
        for service in detector.services:
            assert service.startswith("https://"), f"Insecure service: {service}"

    @patch("urllib.request.urlopen")
    def test_detect_ip_unicode_handling(self, mock_urlopen):
        """Handling of Unicode in responses."""
        mock_response = Mock()
        mock_response.read.return_value = '{"ip": "203.0.113.42"}'.encode("utf-8")
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        detector = IPDetector()
        ip = detector.detect_ip()

        assert ip == "203.0.113.42"

    @patch("urllib.request.urlopen")
    def test_unexpected_exception_handling(self, mock_urlopen):
        """Handling of unexpected exceptions."""
        mock_urlopen.side_effect = RuntimeError("Unexpected error")

        detector = IPDetector()
        with pytest.raises(IPDetectionError):
            detector.detect_ip()
