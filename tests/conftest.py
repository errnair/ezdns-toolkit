"""Pytest configuration and fixtures for ezdns tests."""

import pytest
from unittest.mock import Mock, MagicMock
import dns.resolver


@pytest.fixture
def mock_dns_resolver():
    """Create a mock DNS resolver for testing."""
    resolver = Mock(spec=dns.resolver.Resolver)
    resolver.timeout = 5.0
    resolver.lifetime = 10.0
    return resolver


@pytest.fixture
def sample_domain():
    """Provide a sample valid domain for testing."""
    return "example.com"


@pytest.fixture
def sample_invalid_domain():
    """Provide a sample invalid domain for testing."""
    return "invalid..domain"


@pytest.fixture
def sample_ip_address():
    """Provide a sample IP address for testing."""
    return "192.0.2.1"


@pytest.fixture
def mock_whois_data():
    """Create mock WHOIS data for testing."""
    mock_data = Mock()
    mock_data.name_servers = ['ns1.example.com', 'ns2.example.com']
    mock_data.registrar = 'Example Registrar Inc.'
    mock_data.creation_date = '2020-01-01'
    mock_data.expiration_date = '2025-01-01'
    mock_data.updated_date = '2024-01-01'
    mock_data.status = ['clientTransferProhibited']
    mock_data.emails = ['admin@example.com']
    mock_data.name = 'John Doe'
    mock_data.org = 'Example Organization'
    return mock_data


@pytest.fixture
def mock_dns_answers():
    """Create mock DNS answers for testing."""
    answers = []
    for i in range(3):
        mock_answer = Mock()
        mock_answer.__str__ = Mock(return_value=f'192.0.2.{i}')
        answers.append(mock_answer)
    return answers


@pytest.fixture
def mock_http_response():
    """Create mock HTTP response for IP detection testing."""
    response = Mock()
    response.read = Mock(return_value=b'{"ip": "203.0.113.1"}')
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    return response
