"""Unit tests for DNS resolver module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import dns.resolver
import dns.exception

from ezdns.core.dns_resolver import DNSResolver, get_a_records
from ezdns.utils.exceptions import (
    DNSQueryError,
    DNSTimeoutError,
    DNSNoRecordsError,
    InvalidDomainError,
)


class TestDNSResolver:
    """DNSResolver class."""

    def test_initialization_default(self):
        """DNSResolver initializes with default settings."""
        resolver = DNSResolver()
        assert resolver.resolver is not None
        assert resolver.resolver.timeout > 0
        assert resolver.resolver.lifetime > 0

    def test_initialization_custom_timeout(self):
        """DNSResolver accepts custom timeout."""
        resolver = DNSResolver(timeout=15.0)
        assert resolver.resolver.timeout == 15.0

    def test_initialization_custom_nameservers(self):
        """DNSResolver accepts custom nameservers."""
        custom_ns = ['8.8.8.8', '8.8.4.4']
        resolver = DNSResolver(nameservers=custom_ns)
        assert resolver.resolver.nameservers == custom_ns

    @patch('dns.resolver.Resolver.resolve')
    def test_get_a_records_success(self, mock_resolve):
        """Successful A record query."""
        # Setup mock
        mock_answer = Mock()
        mock_answer.__str__ = Mock(return_value='93.184.216.34')
        mock_resolve.return_value = [mock_answer]

        # Execute
        resolver = DNSResolver()
        records = resolver.get_a_records('example.com')

        # Verify
        assert records == ['93.184.216.34']
        mock_resolve.assert_called_once_with('example.com', 'A')

    @patch('dns.resolver.Resolver.resolve')
    def test_get_a_records_multiple(self, mock_resolve):
        """A record query returning multiple results."""
        # Setup mock
        mock_answers = []
        for i in range(1, 4):
            mock_answer = Mock()
            mock_answer.__str__ = Mock(return_value=f'192.0.2.{i}')
            mock_answers.append(mock_answer)
        mock_resolve.return_value = mock_answers

        # Execute
        resolver = DNSResolver()
        records = resolver.get_a_records('example.com')

        # Verify
        assert len(records) == 3
        assert '192.0.2.1' in records
        assert '192.0.2.3' in records

    @patch('dns.resolver.Resolver.resolve')
    def test_get_a_records_timeout(self, mock_resolve):
        """A record query timeout handling."""
        mock_resolve.side_effect = dns.resolver.Timeout()

        resolver = DNSResolver()
        with pytest.raises(DNSTimeoutError) as exc_info:
            resolver.get_a_records('example.com')

        assert 'example.com' in str(exc_info.value)
        assert 'timed out' in str(exc_info.value).lower()

    @patch('dns.resolver.Resolver.resolve')
    def test_get_a_records_nxdomain(self, mock_resolve):
        """A record query for non-existent domain."""
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        resolver = DNSResolver()
        with pytest.raises(DNSQueryError) as exc_info:
            resolver.get_a_records('nonexistent.example')

        assert 'NXDOMAIN' in str(exc_info.value)

    @patch('dns.resolver.Resolver.resolve')
    def test_get_a_records_no_answer(self, mock_resolve):
        """A record query with no answer."""
        mock_resolve.side_effect = dns.resolver.NoAnswer()

        resolver = DNSResolver()
        with pytest.raises(DNSNoRecordsError) as exc_info:
            resolver.get_a_records('example.com')

        assert 'example.com' in str(exc_info.value)

    def test_get_a_records_invalid_domain(self):
        """A record query with invalid domain."""
        resolver = DNSResolver()
        with pytest.raises(InvalidDomainError):
            resolver.get_a_records('invalid..domain')

    @patch('dns.resolver.Resolver.resolve')
    def test_get_aaaa_records_success(self, mock_resolve):
        """Successful AAAA record query."""
        mock_answer = Mock()
        mock_answer.__str__ = Mock(return_value='2606:2800:220:1:248:1893:25c8:1946')
        mock_resolve.return_value = [mock_answer]

        resolver = DNSResolver()
        records = resolver.get_aaaa_records('example.com')

        assert len(records) == 1
        assert '2606:2800:220:1:248:1893:25c8:1946' in records[0]
        mock_resolve.assert_called_once_with('example.com', 'AAAA')

    @patch('dns.resolver.Resolver.resolve')
    def test_get_mx_records_success(self, mock_resolve):
        """Successful MX record query."""
        mock_answers = []
        for priority, server in [(10, 'mail1.example.com.'), (20, 'mail2.example.com.')]:
            mock_answer = Mock()
            mock_answer.__str__ = Mock(return_value=f'{priority} {server}')
            mock_answers.append(mock_answer)
        mock_resolve.return_value = mock_answers

        resolver = DNSResolver()
        records = resolver.get_mx_records('example.com')

        assert len(records) == 2
        assert '10 mail1.example.com.' in records
        mock_resolve.assert_called_once_with('example.com', 'MX')

    @patch('dns.resolver.Resolver.resolve')
    def test_get_txt_records_success(self, mock_resolve):
        """Successful TXT record query."""
        mock_answer = Mock()
        mock_answer.__str__ = Mock(return_value='"v=spf1 mx -all"')
        mock_resolve.return_value = [mock_answer]

        resolver = DNSResolver()
        records = resolver.get_txt_records('example.com')

        assert len(records) == 1
        assert 'spf1' in records[0]
        mock_resolve.assert_called_once_with('example.com', 'TXT')

    @patch('dns.resolver.Resolver.resolve')
    def test_get_ns_records_success(self, mock_resolve):
        """Successful NS record query."""
        mock_answers = []
        for ns in ['ns1.example.com.', 'ns2.example.com.']:
            mock_answer = Mock()
            mock_answer.__str__ = Mock(return_value=ns)
            mock_answers.append(mock_answer)
        mock_resolve.return_value = mock_answers

        resolver = DNSResolver()
        records = resolver.get_ns_records('example.com')

        assert len(records) == 2
        assert 'ns1.example.com.' in records
        mock_resolve.assert_called_once_with('example.com', 'NS')

    @patch('dns.resolver.Resolver.resolve')
    def test_get_cname_records_success(self, mock_resolve):
        """Successful CNAME record query."""
        mock_answer = Mock()
        mock_answer.__str__ = Mock(return_value='example.com.')
        mock_resolve.return_value = [mock_answer]

        resolver = DNSResolver()
        records = resolver.get_cname_records('www.example.com')

        assert len(records) == 1
        assert 'example.com.' in records[0]
        mock_resolve.assert_called_once_with('www.example.com', 'CNAME')

    @patch('dns.resolver.Resolver.resolve')
    def test_get_soa_record_success(self, mock_resolve):
        """Successful SOA record query."""
        mock_answer = Mock()
        mock_answer.__str__ = Mock(return_value='ns1.example.com. admin.example.com. 2024010801 7200 3600 1209600 86400')
        mock_resolve.return_value = [mock_answer]

        resolver = DNSResolver()
        record = resolver.get_soa_record('example.com')

        assert record is not None
        assert 'ns1.example.com' in record
        mock_resolve.assert_called_once_with('example.com', 'SOA')

    @patch('dns.resolver.Resolver.resolve')
    def test_get_caa_records_success(self, mock_resolve):
        """Successful CAA record query."""
        mock_answer = Mock()
        mock_answer.__str__ = Mock(return_value='0 issue "letsencrypt.org"')
        mock_resolve.return_value = [mock_answer]

        resolver = DNSResolver()
        records = resolver.get_caa_records('example.com')

        assert len(records) == 1
        assert 'letsencrypt.org' in records[0]
        mock_resolve.assert_called_once_with('example.com', 'CAA')

    @patch('dns.reversename.from_address')
    @patch('dns.resolver.Resolver.resolve')
    def test_get_ptr_record_success(self, mock_resolve, mock_reversename):
        """Successful PTR record query."""
        mock_reversename.return_value = '34.216.184.93.in-addr.arpa.'
        mock_answer = Mock()
        mock_answer.__str__ = Mock(return_value='example.com.')
        mock_resolve.return_value = [mock_answer]

        resolver = DNSResolver()
        records = resolver.get_ptr_record('93.184.216.34')

        assert len(records) == 1
        assert 'example.com.' in records[0]
        mock_reversename.assert_called_once_with('93.184.216.34')

    @patch('dns.resolver.Resolver.resolve')
    def test_get_all_records_success(self, mock_resolve):
        """Getting all DNS records at once."""
        def mock_resolve_side_effect(domain, record_type):
            responses = {
                'A': [Mock(__str__=Mock(return_value='93.184.216.34'))],
                'AAAA': [Mock(__str__=Mock(return_value='2606:2800:220::1'))],
                'MX': [Mock(__str__=Mock(return_value='10 mail.example.com.'))],
                'TXT': [Mock(__str__=Mock(return_value='"v=spf1 mx -all"'))],
                'NS': [Mock(__str__=Mock(return_value='ns1.example.com.'))],
            }
            return responses.get(record_type, [])

        mock_resolve.side_effect = mock_resolve_side_effect

        resolver = DNSResolver()
        all_records = resolver.get_all_records('example.com')

        assert 'A' in all_records
        assert 'AAAA' in all_records
        assert 'MX' in all_records
        assert len(all_records['A']) > 0

    @patch('dns.resolver.Resolver.resolve')
    def test_get_all_records_partial_failure(self, mock_resolve):
        """Getting all records when some queries fail."""
        def mock_resolve_side_effect(domain, record_type):
            if record_type == 'A':
                return [Mock(__str__=Mock(return_value='93.184.216.34'))]
            elif record_type == 'AAAA':
                raise dns.resolver.NoAnswer()
            else:
                return []

        mock_resolve.side_effect = mock_resolve_side_effect

        resolver = DNSResolver()
        all_records = resolver.get_all_records('example.com')

        # Should return partial results, not fail completely
        assert 'A' in all_records
        assert len(all_records['A']) == 1
        assert 'AAAA' in all_records
        assert len(all_records['AAAA']) == 0  # Empty list for failed query

    @patch('dns.resolver.Resolver.resolve')
    def test_get_all_records_no_nameservers(self, mock_resolve):
        """Handling of no nameservers error."""
        mock_resolve.side_effect = dns.resolver.NoNameservers()

        resolver = DNSResolver()
        all_records = resolver.get_all_records('example.com')

        # Should return empty lists, not crash
        assert all(len(records) == 0 for records in all_records.values())


class TestConvenienceFunctions:
    """Module-level convenience functions."""

    @patch('ezdns.core.dns_resolver.DNSResolver.get_a_records')
    def test_get_a_records_convenience(self, mock_method):
        """Convenience function for A records."""
        mock_method.return_value = ['93.184.216.34']

        records = get_a_records('example.com')

        assert records == ['93.184.216.34']
        mock_method.assert_called_once()

    @patch('ezdns.core.dns_resolver.DNSResolver.get_a_records')
    def test_get_a_records_convenience_with_timeout(self, mock_method):
        """Convenience function with custom timeout."""
        mock_method.return_value = ['93.184.216.34']

        records = get_a_records('example.com', timeout=10.0)

        assert records == ['93.184.216.34']


class TestDNSResolverEdgeCases:
    """Edge cases and error conditions."""

    @patch('dns.resolver.Resolver.resolve')
    def test_empty_response(self, mock_resolve):
        """Handling of empty DNS response."""
        mock_resolve.return_value = []

        resolver = DNSResolver()
        records = resolver.get_a_records('example.com')

        assert records == []

    @patch('dns.resolver.Resolver.resolve')
    def test_dns_exception(self, mock_resolve):
        """Handling of generic DNS exception."""
        mock_resolve.side_effect = dns.exception.DNSException('Generic DNS error')

        resolver = DNSResolver()
        with pytest.raises(DNSQueryError) as exc_info:
            resolver.get_a_records('example.com')

        assert 'Generic DNS error' in str(exc_info.value)

    @patch('dns.resolver.Resolver.resolve')
    def test_unexpected_exception(self, mock_resolve):
        """Handling of unexpected exception."""
        mock_resolve.side_effect = RuntimeError('Unexpected error')

        resolver = DNSResolver()
        with pytest.raises(DNSQueryError) as exc_info:
            resolver.get_a_records('example.com')

        assert 'Unexpected error' in str(exc_info.value)

    def test_domain_normalization(self):
        """Domains are normalized before querying."""
        resolver = DNSResolver()

        # These should all be normalized to the same domain
        test_domains = [
            'EXAMPLE.COM',
            'example.com',
            '  example.com  ',
            'example.com.',
        ]

        for domain in test_domains:
            with patch('dns.resolver.Resolver.resolve') as mock_resolve:
                mock_resolve.return_value = [Mock(__str__=Mock(return_value='93.184.216.34'))]
                resolver.get_a_records(domain)
                # Should be normalized to lowercase without trailing dot
                called_domain = mock_resolve.call_args[0][0]
                assert called_domain == 'example.com'
