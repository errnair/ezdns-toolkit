"""Integration tests for CLI interface."""

import pytest
from unittest.mock import patch, Mock
import sys
from io import StringIO

from ezdns.cli import main, create_parser


class TestCLIParser:
    """CLI argument parser."""

    def test_parser_creation(self):
        """Parser is created successfully."""
        parser = create_parser()
        assert parser is not None
        assert parser.prog == 'ezdns'

    def test_parser_help(self, capsys):
        """Parser help output."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(['--help'])

        captured = capsys.readouterr()
        assert 'DNS lookup' in captured.out or 'domain information' in captured.out

    def test_parser_version(self, capsys):
        """Parser version output."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(['--version'])

        captured = capsys.readouterr()
        assert 'ezdns' in captured.out

    def test_parser_myip_flag(self):
        """Parsing --myip flag."""
        parser = create_parser()
        args = parser.parse_args(['--myip'])
        assert args.myip is True

    def test_parser_a_records(self):
        """Parsing A record argument."""
        parser = create_parser()
        args = parser.parse_args(['-a', 'example.com'])
        assert args.a == 'example.com'

    def test_parser_nameservers(self):
        """Parsing nameservers argument."""
        parser = create_parser()
        args = parser.parse_args(['--nameservers', 'example.com'])
        assert args.nameservers == 'example.com'

    def test_parser_format_option(self):
        """Parsing format option."""
        parser = create_parser()
        args = parser.parse_args(['-a', 'example.com', '--format', 'json'])
        assert args.format == 'json'

    def test_parser_verbose_flag(self):
        """Parsing verbose flag."""
        parser = create_parser()
        args = parser.parse_args(['-a', 'example.com', '--verbose'])
        assert args.verbose is True


class TestCLIMain:
    """Main CLI function."""

    def test_main_no_arguments(self, capsys):
        """"Main with no arguments shows help."""
        with patch('sys.argv', ['ezdns']):
            exit_code = main()

        assert exit_code == 1

    @patch('ezdns.cli.get_public_ip')
    def test_main_myip_success(self, mock_get_ip, capsys):
        """Successful IP detection via CLI."""
        mock_get_ip.return_value = '203.0.113.42'

        with patch('sys.argv', ['ezdns', '--myip']):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert '203.0.113.42' in captured.out

    @patch('ezdns.cli.get_public_ip')
    def test_main_myip_failure(self, mock_get_ip, capsys):
        """IP detection failure via CLI."""
        from ezdns.utils.exceptions import IPDetectionError
        mock_get_ip.side_effect = IPDetectionError(reason='All services failed')

        with patch('sys.argv', ['ezdns', '--myip']):
            exit_code = main()

        assert exit_code == 1

    @patch('ezdns.cli.DNSResolver')
    def test_main_a_records_success(self, mock_resolver_class, capsys):
        """Successful A record query via CLI."""
        mock_resolver = Mock()
        mock_resolver.get_a_records.return_value = ['93.184.216.34']
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '-a', 'example.com']):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert '93.184.216.34' in captured.out

    @patch('ezdns.cli.DNSResolver')
    def test_main_a_records_invalid_domain(self, mock_resolver_class, capsys):
        """A record query with invalid domain."""
        from ezdns.utils.exceptions import InvalidDomainError
        mock_resolver = Mock()
        mock_resolver.get_a_records.side_effect = InvalidDomainError('invalid..domain')
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '-a', 'invalid..domain']):
            exit_code = main()

        assert exit_code == 1
        captured = capsys.readouterr()
        assert 'Error' in captured.err or 'Invalid' in captured.err

    @patch('ezdns.cli.DNSResolver')
    def test_main_a_records_json_format(self, mock_resolver_class, capsys):
        """A record query with JSON output."""
        import json
        mock_resolver = Mock()
        mock_resolver.get_a_records.return_value = ['93.184.216.34']
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '-a', 'example.com', '--format', 'json']):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()

        # Should be valid JSON
        try:
            data = json.loads(captured.out)
            assert 'domain' in data
            assert 'records' in data
        except json.JSONDecodeError:
            pytest.fail('Output is not valid JSON')

    @patch('ezdns.cli.DNSResolver')
    @patch('ezdns.cli.WHOISLookup')
    def test_main_nameservers(self, mock_whois_class, mock_resolver_class, capsys):
        """Nameservers query via CLI."""
        mock_resolver = Mock()
        mock_resolver.get_ns_records.return_value = ['ns1.example.com.']
        mock_resolver_class.return_value = mock_resolver

        mock_whois = Mock()
        mock_whois.get_nameservers.return_value = ['ns1.example.com']
        mock_whois_class.return_value = mock_whois

        with patch('sys.argv', ['ezdns', '--nameservers', 'example.com']):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert 'ns1.example.com' in captured.out
        assert 'Nameservers' in captured.out

    @patch('ezdns.cli.DNSResolver')
    def test_main_list_all_records(self, mock_resolver_class, capsys):
        """Listing all DNS records via CLI."""
        mock_resolver = Mock()
        mock_resolver.get_ns_records.return_value = ['ns1.example.com.']
        mock_resolver.get_all_records.return_value = {
            'A': ['93.184.216.34'],
            'MX': ['10 mail.example.com.'],
            'TXT': ['"v=spf1 mx -all"'],
        }
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '--list', 'example.com']):
            # Also need to patch WHOIS
            with patch('ezdns.cli.WHOISLookup') as mock_whois_class:
                mock_whois = Mock()
                mock_whois.get_nameservers.return_value = ['ns1.example.com']
                mock_whois_class.return_value = mock_whois

                exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert '93.184.216.34' in captured.out
        assert 'mail.example.com' in captured.out

    def test_main_keyboard_interrupt(self, capsys):
        """Handling of keyboard interrupt."""
        with patch('ezdns.cli.get_public_ip') as mock_get_ip:
            mock_get_ip.side_effect = KeyboardInterrupt()

            with patch('sys.argv', ['ezdns', '--myip']):
                exit_code = main()

        assert exit_code == 130
        captured = capsys.readouterr()
        assert 'Interrupted' in captured.err

    def test_main_invalid_format(self, capsys):
        """Handling of invalid output format."""
        with patch('sys.argv', ['ezdns', '-a', 'example.com', '--format', 'invalid']):
            exit_code = main()

        assert exit_code == 1


class TestCLIHandlers:
    """Individual CLI handler functions."""

    @patch('ezdns.cli.DNSResolver')
    def test_handle_dns_query_aaaa(self, mock_resolver_class, capsys):
        """AAAA record query handler."""
        mock_resolver = Mock()
        mock_resolver.get_aaaa_records.return_value = ['2606:2800:220::1']
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '--aaaa', 'example.com']):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert '2606:2800:220::1' in captured.out

    @patch('ezdns.cli.DNSResolver')
    def test_handle_dns_query_mx(self, mock_resolver_class, capsys):
        """MX record query handler."""
        mock_resolver = Mock()
        mock_resolver.get_mx_records.return_value = ['10 mail.example.com.']
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '--mx', 'example.com']):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert 'mail.example.com' in captured.out

    @patch('ezdns.cli.DNSResolver')
    def test_handle_dns_query_txt(self, mock_resolver_class, capsys):
        """TXT record query handler."""
        mock_resolver = Mock()
        mock_resolver.get_txt_records.return_value = ['"v=spf1 mx -all"']
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '--txt', 'example.com']):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert 'spf1' in captured.out

    @patch('ezdns.cli.DNSResolver')
    def test_handle_dns_query_cname(self, mock_resolver_class, capsys):
        """CNAME record query handler."""
        mock_resolver = Mock()
        mock_resolver.get_cname_records.return_value = ['example.com.']
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '--cname', 'www.example.com']):
            exit_code = main()

        assert exit_code == 0

    @patch('ezdns.cli.DNSResolver')
    def test_handle_ptr_query(self, mock_resolver_class, capsys):
        """PTR record query handler."""
        mock_resolver = Mock()
        mock_resolver.get_ptr_record.return_value = ['example.com.']
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '--ptr', '93.184.216.34']):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert 'example.com' in captured.out

    @patch('ezdns.cli.WHOISLookup')
    def test_handle_whois_query(self, mock_whois_class, capsys):
        """WHOIS query handler."""
        mock_whois = Mock()
        mock_whois.query.return_value = {
            'nameservers': ['ns1.example.com'],
            'registrar': 'Example Registrar Inc.',
            'creation_date': '2020-01-01',
            'expiration_date': '2025-01-01',
        }
        mock_whois_class.return_value = mock_whois

        with patch('sys.argv', ['ezdns', '--whois', 'example.com']):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert 'Example Registrar' in captured.out


class TestCLILogging:
    """CLI logging functionality."""

    @patch('ezdns.cli.DNSResolver')
    def test_verbose_logging(self, mock_resolver_class, capsys):
        """Verbose logging output."""
        mock_resolver = Mock()
        mock_resolver.get_a_records.return_value = ['93.184.216.34']
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '-a', 'example.com', '--verbose']):
            exit_code = main()

        # Verbose mode should work without errors
        assert exit_code == 0


class TestCLIErrorHandling:
    """CLI error handling."""

    @patch('ezdns.cli.DNSResolver')
    def test_no_records_found(self, mock_resolver_class, capsys):
        """Handling of no records found."""
        from ezdns.utils.exceptions import DNSNoRecordsError
        mock_resolver = Mock()
        mock_resolver.get_a_records.side_effect = DNSNoRecordsError('A', 'example.com')
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '-a', 'example.com']):
            exit_code = main()

        # Should succeed but show no records
        assert exit_code == 0
        captured = capsys.readouterr()
        assert 'No' in captured.out and 'records' in captured.out

    @patch('ezdns.cli.DNSResolver')
    def test_dns_timeout(self, mock_resolver_class, capsys):
        """Handling of DNS timeout."""
        from ezdns.utils.exceptions import DNSTimeoutError
        mock_resolver = Mock()
        mock_resolver.get_a_records.side_effect = DNSTimeoutError('A', 'example.com')
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '-a', 'example.com']):
            exit_code = main()

        # Should fail with error
        assert exit_code == 1

    @patch('ezdns.cli.DNSResolver')
    def test_unexpected_exception(self, mock_resolver_class, capsys):
        """Handling of unexpected exception."""
        mock_resolver = Mock()
        mock_resolver.get_a_records.side_effect = RuntimeError('Unexpected error')
        mock_resolver_class.return_value = mock_resolver

        with patch('sys.argv', ['ezdns', '-a', 'example.com']):
            exit_code = main()

        # Should fail gracefully
        assert exit_code == 1
