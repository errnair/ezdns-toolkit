"""Unit tests for WHOIS lookup module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from ezdns.core.whois_lookup import WHOISLookup, get_whois_info, get_whois_nameservers
from ezdns.utils.exceptions import WHOISQueryError, InvalidDomainError


class TestWHOISLookup:
    """WHOISLookup class."""

    def test_initialization_default(self):
        """WHOISLookup initializes with default settings."""
        lookup = WHOISLookup()
        assert lookup.timeout > 0

    def test_initialization_custom_timeout(self):
        """WHOISLookup accepts custom timeout."""
        lookup = WHOISLookup(timeout=20.0)
        assert lookup.timeout == 20.0

    @patch('whois.whois')
    def test_query_success(self, mock_whois):
        """Successful WHOIS query."""
        # Setup mock
        mock_data = Mock()
        mock_data.name_servers = ['NS1.EXAMPLE.COM', 'NS2.EXAMPLE.COM']
        mock_data.registrar = 'Example Registrar Inc.'
        mock_data.creation_date = datetime(2020, 1, 1)
        mock_data.expiration_date = datetime(2025, 1, 1)
        mock_data.updated_date = datetime(2024, 1, 1)
        mock_data.status = 'clientTransferProhibited'
        mock_data.emails = 'admin@example.com'
        mock_data.name = 'John Doe'
        mock_data.org = 'Example Org'
        mock_whois.return_value = mock_data

        # Execute
        lookup = WHOISLookup()
        result = lookup.query('example.com')

        # Verify
        assert 'nameservers' in result
        assert len(result['nameservers']) == 2
        assert 'ns1.example.com' in result['nameservers']
        assert 'ns2.example.com' in result['nameservers']
        assert result['registrar'] == 'Example Registrar Inc.'
        assert '2020-01-01' in result['creation_date']
        assert '2025-01-01' in result['expiration_date']
        mock_whois.assert_called_once_with('example.com')

    @patch('whois.whois')
    def test_query_nameservers_deduplication(self, mock_whois):
        """Duplicate nameservers are removed."""
        mock_data = Mock()
        # Duplicates with different cases
        mock_data.name_servers = ['NS1.EXAMPLE.COM', 'ns1.example.com', 'NS2.EXAMPLE.COM']
        mock_data.registrar = None
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.status = None
        mock_data.emails = None
        mock_data.name = None
        mock_data.org = None
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()
        result = lookup.query('example.com')

        # Should have only 2 unique nameservers (case-insensitive)
        assert len(result['nameservers']) == 2
        assert 'ns1.example.com' in result['nameservers']
        assert 'ns2.example.com' in result['nameservers']

    @patch('whois.whois')
    def test_query_list_fields(self, mock_whois):
        """Handling of fields that can be lists."""
        mock_data = Mock()
        mock_data.name_servers = ['ns1.example.com', 'ns2.example.com']
        mock_data.registrar = 'Example Registrar'
        # These can be lists with multiple dates
        mock_data.creation_date = [datetime(2020, 1, 1), datetime(2020, 1, 2)]
        mock_data.expiration_date = [datetime(2025, 1, 1), datetime(2025, 1, 2)]
        mock_data.updated_date = [datetime(2024, 1, 1)]
        mock_data.status = ['clientTransferProhibited', 'clientDeleteProhibited']
        mock_data.emails = ['admin@example.com', 'tech@example.com']
        mock_data.name = 'John Doe'
        mock_data.org = 'Example Org'
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()
        result = lookup.query('example.com')

        # Should take first date from lists
        assert '2020-01-01' in result['creation_date']
        assert '2025-01-01' in result['expiration_date']
        # Status should remain as list
        assert isinstance(result['status'], list)
        assert len(result['status']) == 2
        # Emails should remain as list
        assert isinstance(result['emails'], list)
        assert len(result['emails']) == 2

    @patch('whois.whois')
    def test_query_missing_fields(self, mock_whois):
        """Handling of missing WHOIS fields."""
        mock_data = Mock()
        # Only set nameservers, leave others as None/missing
        mock_data.name_servers = ['ns1.example.com']
        mock_data.registrar = None
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.status = None
        mock_data.emails = None
        # Don't set name/org attributes at all
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()
        result = lookup.query('example.com')

        # Should handle missing fields gracefully
        assert result['nameservers'] == ['ns1.example.com']
        assert result['registrar'] is None
        assert result['creation_date'] is None
        assert result['status'] == []
        assert result['emails'] == []

    @patch('whois.whois')
    def test_query_no_data(self, mock_whois):
        """WHOIS query returning no data."""
        mock_whois.return_value = None

        lookup = WHOISLookup()
        with pytest.raises(WHOISQueryError) as exc_info:
            lookup.query('example.com')

        assert 'No WHOIS data returned' in str(exc_info.value)

    @patch('whois.whois')
    def test_query_parser_error(self, mock_whois):
        """Handling of WHOIS parser errors."""
        from whois.parser import PywhoisError
        mock_whois.side_effect = PywhoisError('Parse error')

        lookup = WHOISLookup()
        with pytest.raises(WHOISQueryError) as exc_info:
            lookup.query('example.com')

        assert 'Parser error' in str(exc_info.value)

    @patch('whois.whois')
    def test_query_generic_exception(self, mock_whois):
        """Handling of generic exceptions."""
        mock_whois.side_effect = Exception('Connection failed')

        lookup = WHOISLookup()
        with pytest.raises(WHOISQueryError) as exc_info:
            lookup.query('example.com')

        assert 'Connection failed' in str(exc_info.value)

    def test_query_invalid_domain(self):
        """WHOIS query with invalid domain."""
        lookup = WHOISLookup()
        with pytest.raises(InvalidDomainError):
            lookup.query('invalid..domain')

    @patch('whois.whois')
    def test_get_nameservers_success(self, mock_whois):
        """Getting just nameservers from WHOIS."""
        mock_data = Mock()
        mock_data.name_servers = ['ns1.example.com', 'ns2.example.com']
        mock_data.registrar = 'Test'
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.status = None
        mock_data.emails = None
        mock_data.name = None
        mock_data.org = None
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()
        nameservers = lookup.get_nameservers('example.com')

        assert len(nameservers) == 2
        assert 'ns1.example.com' in nameservers

    @patch('whois.whois')
    def test_get_registrar_success(self, mock_whois):
        """Getting just registrar from WHOIS."""
        mock_data = Mock()
        mock_data.name_servers = ['ns1.example.com']
        mock_data.registrar = 'Example Registrar Inc.'
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.status = None
        mock_data.emails = None
        mock_data.name = None
        mock_data.org = None
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()
        registrar = lookup.get_registrar('example.com')

        assert registrar == 'Example Registrar Inc.'

    @patch('whois.whois')
    def test_domain_normalization(self, mock_whois):
        """Domains are normalized before WHOIS query."""
        mock_data = Mock()
        mock_data.name_servers = ['ns1.example.com']
        mock_data.registrar = None
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.status = None
        mock_data.emails = None
        mock_data.name = None
        mock_data.org = None
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()

        # Test various forms of the same domain
        test_domains = [
            'EXAMPLE.COM',
            'example.com',
            '  example.com  ',
            'example.com.',
        ]

        for domain in test_domains:
            mock_whois.reset_mock()
            lookup.query(domain)
            # Should be normalized to lowercase without trailing dot
            called_domain = mock_whois.call_args[0][0]
            assert called_domain == 'example.com'


class TestConvenienceFunctions:
    """Module-level convenience functions."""

    @patch('ezdns.core.whois_lookup.WHOISLookup.query')
    def test_get_whois_info_convenience(self, mock_query):
        """Convenience function for WHOIS info."""
        mock_query.return_value = {
            'nameservers': ['ns1.example.com'],
            'registrar': 'Example Registrar',
        }

        result = get_whois_info('example.com')

        assert result['registrar'] == 'Example Registrar'
        mock_query.assert_called_once()

    @patch('ezdns.core.whois_lookup.WHOISLookup.get_nameservers')
    def test_get_whois_nameservers_convenience(self, mock_method):
        """Convenience function for WHOIS nameservers."""
        mock_method.return_value = ['ns1.example.com', 'ns2.example.com']

        nameservers = get_whois_nameservers('example.com')

        assert len(nameservers) == 2
        mock_method.assert_called_once()


class TestWHOISDataParsing:
    """WHOIS data parsing logic."""

    @patch('whois.whois')
    def test_parse_nameservers_single_string(self, mock_whois):
        """Parsing nameservers when returned as single string."""
        mock_data = Mock()
        mock_data.name_servers = 'ns1.example.com'  # Single string, not list
        mock_data.registrar = None
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.status = None
        mock_data.emails = None
        mock_data.name = None
        mock_data.org = None
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()
        result = lookup.query('example.com')

        # Should convert to list
        assert isinstance(result['nameservers'], list)
        assert 'ns1.example.com' in result['nameservers']

    @patch('whois.whois')
    def test_parse_status_single_string(self, mock_whois):
        """Parsing status when returned as single string."""
        mock_data = Mock()
        mock_data.name_servers = ['ns1.example.com']
        mock_data.registrar = None
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.status = 'clientTransferProhibited'  # Single string
        mock_data.emails = None
        mock_data.name = None
        mock_data.org = None
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()
        result = lookup.query('example.com')

        # Should convert to list
        assert isinstance(result['status'], list)
        assert 'clientTransferProhibited' in result['status']

    @patch('whois.whois')
    def test_parse_emails_single_string(self, mock_whois):
        """Parsing emails when returned as single string."""
        mock_data = Mock()
        mock_data.name_servers = ['ns1.example.com']
        mock_data.registrar = None
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.status = None
        mock_data.emails = 'admin@example.com'  # Single string
        mock_data.name = None
        mock_data.org = None
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()
        result = lookup.query('example.com')

        # Should convert to list
        assert isinstance(result['emails'], list)
        assert 'admin@example.com' in result['emails']

    @patch('whois.whois')
    def test_parse_empty_nameservers(self, mock_whois):
        """Parsing when nameservers list is empty."""
        mock_data = Mock()
        mock_data.name_servers = []
        mock_data.registrar = None
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.status = None
        mock_data.emails = None
        mock_data.name = None
        mock_data.org = None
        mock_whois.return_value = mock_data

        lookup = WHOISLookup()
        result = lookup.query('example.com')

        assert result['nameservers'] == []
