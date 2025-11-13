"""Unit tests for validation utilities."""

import pytest
from ezdns.utils.validators import (
    is_valid_domain,
    validate_domain,
    is_ipv4,
    is_ipv6,
    is_valid_domain_label,
)
from ezdns.utils.exceptions import InvalidDomainError


class TestDomainValidation:
    """Domain validation tests."""

    def test_valid_domain(self):
        """Valid domains pass."""
        valid_domains = [
            'example.com',
            'subdomain.example.com',
            'test-domain.co.uk',
            'my-site123.com',
            'a.b.c.d.example.com',
        ]
        for domain in valid_domains:
            assert is_valid_domain(domain), f'{domain} should be valid'

    def test_invalid_domain(self):
        """Invalid domains rejected."""
        invalid_domains = [
            '',
            'a',
            'example',  # No TLD
            'example.',
            '-example.com',  # Starts with hyphen
            'example-.com',  # Ends with hyphen
            'exa mple.com',  # Contains space
            'example..com',  # Double dot
            'a' * 64 + '.com',  # Label too long
        ]
        for domain in invalid_domains:
            assert not is_valid_domain(domain), f'{domain} should be invalid'

    def test_validate_domain_normalizes(self):
        """Domain normalization works."""
        assert validate_domain('EXAMPLE.COM') == 'example.com'
        assert validate_domain('  example.com  ') == 'example.com'
        assert validate_domain('example.com.') == 'example.com'

    def test_validate_domain_removes_protocol(self):
        """Protocol removed."""
        assert validate_domain('https://example.com') == 'example.com'
        assert validate_domain('http://example.com') == 'example.com'

    def test_validate_domain_removes_path(self):
        """Path removed."""
        assert validate_domain('example.com/path') == 'example.com'
        assert validate_domain('example.com:8080/path') == 'example.com'

    def test_validate_domain_security_checks(self):
        """Security checks work."""
        with pytest.raises(InvalidDomainError):
            validate_domain('example.com\x00')  # Null byte

        with pytest.raises(InvalidDomainError):
            validate_domain('example.com;rm -rf')  # Command injection attempt

        with pytest.raises(InvalidDomainError):
            validate_domain('example.com$(whoami)')  # Command substitution

    def test_validate_domain_empty(self):
        """Empty input rejected."""
        with pytest.raises(InvalidDomainError):
            validate_domain('')

        with pytest.raises(InvalidDomainError):
            validate_domain('   ')

    def test_validate_domain_too_long(self):
        """Long domains rejected."""
        long_domain = 'a' * 250 + '.com'
        with pytest.raises(InvalidDomainError):
            validate_domain(long_domain)


class TestDomainLabelValidation:
    """Domain label validation."""

    def test_valid_label(self):
        """Valid labels pass."""
        valid_labels = ['example', 'test123', 'my-label', 'a', '123']
        for label in valid_labels:
            assert is_valid_domain_label(label), f'{label} should be valid'

    def test_invalid_label(self):
        """Invalid labels rejected."""
        invalid_labels = [
            '',
            '-start',  # Starts with hyphen
            'end-',  # Ends with hyphen
            'a' * 64,  # Too long
            'label with spaces',
        ]
        for label in invalid_labels:
            assert not is_valid_domain_label(label), f'{label} should be invalid'


class TestIPValidation:
    """IP address validation."""

    def test_valid_ipv4(self):
        """Valid IPv4 addresses."""
        valid_ips = [
            '0.0.0.0',
            '192.168.1.1',
            '255.255.255.255',
            '10.0.0.1',
        ]
        for ip in valid_ips:
            assert is_ipv4(ip), f'{ip} should be valid IPv4'

    def test_invalid_ipv4(self):
        """Invalid IPv4 addresses."""
        invalid_ips = [
            '',
            '256.1.1.1',  # Out of range
            '1.1.1',  # Incomplete
            '1.1.1.1.1',  # Too many octets
            'not.an.ip.addr',
            '1.2.3.four',
        ]
        for ip in invalid_ips:
            assert not is_ipv4(ip), f'{ip} should be invalid IPv4'

    def test_valid_ipv6(self):
        """Valid IPv6 addresses."""
        valid_ips = [
            '::1',
            '2001:db8::1',
            'fe80::1',
            '2001:0db8:0000:0000:0000:ff00:0042:8329',
        ]
        for ip in valid_ips:
            assert is_ipv6(ip), f'{ip} should be valid IPv6'

    def test_invalid_ipv6(self):
        """Invalid IPv6 addresses."""
        invalid_ips = [
            '',
            ':::1',  # Too many colons
            '2001:db8::1::2',  # Multiple ::
            'not:an:ipv6:address',
            '12345::1',  # Group too long
        ]
        for ip in invalid_ips:
            assert not is_ipv6(ip), f'{ip} should be invalid IPv6'
