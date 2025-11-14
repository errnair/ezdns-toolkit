"""Unit tests for output formatters."""

import pytest
import json
from unittest.mock import patch

from ezdns.utils.formatters import (
    TextFormatter,
    JSONFormatter,
    CSVFormatter,
    YAMLFormatter,
    get_formatter,
)


class TestTextFormatter:
    """TextFormatter class."""

    def test_format_list_with_items(self):
        """Formatting a list of items."""
        items = ["item1", "item2", "item3"]
        result = TextFormatter.format_list("Test Records", items)

        assert "Test Records" in result
        assert "===" in result
        assert "> item1" in result
        assert "> item2" in result
        assert "> item3" in result

    def test_format_list_empty(self):
        """Formatting an empty list."""
        result = TextFormatter.format_list("Test Records", [])

        assert "Test Records" in result
        assert "No records found" in result

    def test_format_list_custom_indent(self):
        """Formatting with custom indentation."""
        items = ["item1"]
        result = TextFormatter.format_list("Test", items, indent="    ")

        assert "    >" in result

    def test_format_dict(self):
        """Formatting a dictionary."""
        data = {"Key1": ["value1", "value2"], "Key2": ["value3"]}
        result = TextFormatter.format_dict("Test Section", data)

        assert "Test Section" in result
        assert "> Key1" in result
        assert "value1" in result
        assert "value2" in result

    def test_format_dict_empty_values(self):
        """Formatting dict with empty value lists."""
        data = {"Key1": []}
        result = TextFormatter.format_dict("Test", data)

        assert "Key1" in result
        assert "(None)" in result

    def test_format_nameservers(self):
        """Formatting nameserver comparison."""
        whois_ns = ["ns1.example.com", "ns2.example.com"]
        dns_ns = ["ns1.example.com.", "ns2.example.com."]

        result = TextFormatter.format_nameservers(whois_ns, dns_ns)

        assert "Nameservers" in result
        assert "WHOIS NS" in result
        assert "DOMAIN NS" in result
        assert "ns1.example.com" in result

    def test_format_nameservers_empty(self):
        """Formatting with no nameservers."""
        result = TextFormatter.format_nameservers([], [])

        assert "WHOIS NS" in result
        assert "(None)" in result

    def test_format_all_records(self):
        """Formatting all DNS records."""
        records = {
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220::1"],
            "MX": ["10 mail.example.com."],
            "TXT": ['"v=spf1 mx -all"'],
            "NS": ["ns1.example.com."],
            "CNAME": [],
            "SOA": ["ns1.example.com. admin.example.com. 2024010801"],
            "CAA": ['0 issue "letsencrypt.org"'],
        }

        result = TextFormatter.format_all_records(records)

        assert "A Records (IPv4)" in result
        assert "AAAA Records (IPv6)" in result
        assert "MX Records (Mail Exchange)" in result
        assert "93.184.216.34" in result


class TestJSONFormatter:
    """JSONFormatter class."""

    def test_format_basic_data(self):
        """Formatting basic data as JSON."""
        data = {"key": "value", "number": 42}
        result = JSONFormatter.format(data)

        parsed = json.loads(result)
        assert parsed["key"] == "value"
        assert parsed["number"] == 42

    def test_format_pretty_print(self):
        """Pretty printing JSON."""
        data = {"key": "value"}
        result = JSONFormatter.format(data, pretty=True)

        # Pretty printed JSON has newlines and indentation
        assert "\n" in result
        assert "  " in result

    def test_format_compact(self):
        """Compact JSON formatting."""
        data = {"key": "value"}
        result = JSONFormatter.format(data, pretty=False)

        # Compact JSON is single line
        assert result.count("\n") == 0

    def test_format_records(self):
        """Formatting DNS records as JSON."""
        records = ["93.184.216.34", "93.184.216.35"]
        result = JSONFormatter.format_records("example.com", "A", records)

        parsed = json.loads(result)
        assert parsed["domain"] == "example.com"
        assert parsed["record_type"] == "A"
        assert parsed["count"] == 2
        assert len(parsed["records"]) == 2

    def test_format_nameservers(self):
        """Formatting nameservers as JSON."""
        whois_ns = ["ns1.example.com"]
        dns_ns = ["ns1.example.com."]

        result = JSONFormatter.format_nameservers("example.com", whois_ns, dns_ns)

        parsed = json.loads(result)
        assert parsed["domain"] == "example.com"
        assert "nameservers" in parsed
        assert "whois" in parsed["nameservers"]
        assert "dns" in parsed["nameservers"]

    def test_format_all_records(self):
        """Formatting all records as JSON."""
        records = {"A": ["93.184.216.34"], "MX": ["10 mail.example.com."]}

        result = JSONFormatter.format_all_records("example.com", records)

        parsed = json.loads(result)
        assert parsed["domain"] == "example.com"
        assert "records" in parsed
        assert "A" in parsed["records"]

    def test_format_unicode(self):
        """Formatting with Unicode characters."""
        data = {"text": "Unicode: 你好"}
        result = JSONFormatter.format(data)

        parsed = json.loads(result)
        assert parsed["text"] == "Unicode: 你好"


class TestCSVFormatter:
    """CSVFormatter class."""

    def test_format_records_basic(self):
        """Formatting basic records as CSV."""
        records = ["93.184.216.34", "93.184.216.35"]
        result = CSVFormatter.format_records("example.com", "A", records)

        lines = result.split("\n")
        assert lines[0] == "domain,record_type,value"
        assert "example.com,A,93.184.216.34" in lines
        assert "example.com,A,93.184.216.35" in lines

    def test_format_records_with_commas(self):
        """CSV escaping for values containing commas."""
        records = ["value, with, commas"]
        result = CSVFormatter.format_records("example.com", "TXT", records)

        # Should be quoted
        assert '"value, with, commas"' in result

    def test_format_records_with_quotes(self):
        """CSV escaping for values containing quotes."""
        records = ['value "with" quotes']
        result = CSVFormatter.format_records("example.com", "TXT", records)

        # Quotes should be escaped
        assert '""with""' in result

    def test_format_all_records(self):
        """Formatting all records as CSV."""
        records = {"A": ["93.184.216.34"], "MX": ["10 mail.example.com."]}

        result = CSVFormatter.format_all_records("example.com", records)

        lines = result.split("\n")
        assert lines[0] == "domain,record_type,value"
        assert "example.com,A,93.184.216.34" in lines
        assert "example.com,MX,10 mail.example.com." in lines

    def test_format_empty_records(self):
        """Formatting with no records."""
        result = CSVFormatter.format_records("example.com", "A", [])

        lines = result.split("\n")
        # Should only have header
        assert len(lines) == 1
        assert lines[0] == "domain,record_type,value"


class TestYAMLFormatter:
    """YAMLFormatter class."""

    def test_format_basic_data(self):
        """Formatting basic data as YAML."""
        data = {"key": "value", "number": 42}
        result = YAMLFormatter.format(data)

        # Basic checks for YAML format
        assert "key:" in result
        assert "value" in result
        assert "number:" in result

    def test_format_records(self):
        """Formatting DNS records as YAML."""
        records = ["93.184.216.34"]
        result = YAMLFormatter.format_records("example.com", "A", records)

        assert "domain:" in result
        assert "example.com" in result
        assert "record_type:" in result
        assert "records:" in result

    def test_format_all_records(self):
        """Formatting all records as YAML."""
        records = {"A": ["93.184.216.34"], "MX": ["10 mail.example.com."]}

        result = YAMLFormatter.format_all_records("example.com", records)

        assert "domain:" in result
        assert "records:" in result
        assert "A:" in result or "- 93.184.216.34" in result

    def test_format_fallback_to_json_when_yaml_not_available(self):
        """Fallback to JSON when PyYAML is not installed."""
        # This tests the ImportError handling
        import builtins
        from unittest.mock import patch as mock_patch

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named yaml")
            return real_import(name, *args, **kwargs)

        with mock_patch("builtins.__import__", side_effect=mock_import):
            data = {"key": "value"}
            result = YAMLFormatter.format(data)

            # Should be valid JSON
            parsed = json.loads(result)
            assert parsed["key"] == "value"


class TestGetFormatter:
    """get_formatter tests."""

    def test_get_text_formatter(self):
        """Getting TextFormatter."""
        formatter = get_formatter("text")
        assert formatter == TextFormatter

    def test_get_json_formatter(self):
        """Getting JSONFormatter."""
        formatter = get_formatter("json")
        assert formatter == JSONFormatter

    def test_get_csv_formatter(self):
        """Getting CSVFormatter."""
        formatter = get_formatter("csv")
        assert formatter == CSVFormatter

    def test_get_yaml_formatter(self):
        """Getting YAMLFormatter."""
        formatter = get_formatter("yaml")
        assert formatter == YAMLFormatter

    def test_get_formatter_case_insensitive(self):
        """Format type is case insensitive."""
        formatter = get_formatter("JSON")
        assert formatter == JSONFormatter

        formatter = get_formatter("Text")
        assert formatter == TextFormatter

    def test_get_formatter_invalid_type(self):
        """Error handling for invalid format type."""
        with pytest.raises(ValueError) as exc_info:
            get_formatter("invalid")

        assert "Unknown format" in str(exc_info.value)


class TestFormatterIntegration:
    """Integration tests for formatters working together."""

    def test_same_data_different_formats(self):
        """Same data can be formatted in all formats."""
        records = ["93.184.216.34", "93.184.216.35"]
        domain = "example.com"
        record_type = "A"

        # Text format
        text_result = TextFormatter.format_list(f"{record_type} Record(s)", records)
        assert "93.184.216.34" in text_result

        # JSON format
        json_result = JSONFormatter.format_records(domain, record_type, records)
        json_data = json.loads(json_result)
        assert len(json_data["records"]) == 2

        # CSV format
        csv_result = CSVFormatter.format_records(domain, record_type, records)
        assert csv_result.count("\n") == 2  # Header + 2 records

    def test_all_formatters_handle_empty_data(self):
        """All formatters handle empty data gracefully."""
        empty_records = []

        # Should not raise exceptions
        TextFormatter.format_list("Empty", empty_records)
        JSONFormatter.format_records("example.com", "A", empty_records)
        CSVFormatter.format_records("example.com", "A", empty_records)
        YAMLFormatter.format_records("example.com", "A", empty_records)

    def test_all_formatters_handle_special_characters(self):
        """All formatters handle special characters."""
        records = ['"quoted"', "with,comma", "with\nnewline"]

        # Should not raise exceptions
        TextFormatter.format_list("Special", records)
        JSONFormatter.format_records("example.com", "TXT", records)
        CSVFormatter.format_records("example.com", "TXT", records)
        YAMLFormatter.format_records("example.com", "TXT", records)


def patch(target, new=None):
    """Helper to create a patch decorator."""
    from unittest.mock import patch as mock_patch

    return mock_patch(target, new)
