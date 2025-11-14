"""Output formatters for text, JSON, CSV, and YAML."""

import json
import logging
from typing import List, Dict, Any, Type, Union

logger = logging.getLogger(__name__)


class TextFormatter:
    """Formats output as human-readable text."""

    @staticmethod
    def format_list(title: str, items: List[str], indent: str = "  ") -> str:
        """Format list with title."""
        if not items:
            return f"\n{title}\n{'=' * len(title)}\n{indent}(No records found)\n"

        output = [f"\n{title}", "=" * len(title)]
        for item in items:
            output.append(f"{indent}> {item}")
        output.append("")  # Empty line at end
        return "\n".join(output)

    @staticmethod
    def format_dict(title: str, data: Dict[str, List[str]], indent: str = "  ") -> str:
        """Format dictionary with title."""
        output = [f"\n{title}", "=" * len(title)]

        for key, values in data.items():
            output.append(f"{indent}> {key}")
            if values:
                for value in values:
                    output.append(f"\t{value}")
            else:
                output.append(f"\t(None)")

        output.append("")  # Empty line at end
        return "\n".join(output)

    @staticmethod
    def format_nameservers(whois_ns: List[str], dns_ns: List[str]) -> str:
        """Format nameserver comparison."""
        ns_dict = {
            "WHOIS NS": whois_ns if whois_ns else ["(None)"],
            "DOMAIN NS": dns_ns if dns_ns else ["(None)"],
        }
        return TextFormatter.format_dict("Nameservers", ns_dict)

    @staticmethod
    def format_all_records(records: Dict[str, List[str]]) -> str:
        """Format all DNS records."""
        output = []

        record_titles = {
            "A": "A Records (IPv4)",
            "AAAA": "AAAA Records (IPv6)",
            "MX": "MX Records (Mail Exchange)",
            "TXT": "TXT Records",
            "NS": "NS Records (Nameservers)",
            "CNAME": "CNAME Records (Aliases)",
            "SOA": "SOA Record (Start of Authority)",
            "CAA": "CAA Records (Certificate Authority)",
        }

        for record_type, title in record_titles.items():
            if record_type in records:
                output.append(
                    TextFormatter.format_list(f">> {title}", records[record_type], indent="   ")
                )

        return "\n".join(output)


class JSONFormatter:
    """Formats output as JSON."""

    @staticmethod
    def format(data: Any, pretty: bool = True) -> str:
        """Format data as JSON."""
        if pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def format_records(domain: str, record_type: str, records: List[str]) -> str:
        """Format DNS records as JSON."""
        data = {
            "domain": domain,
            "record_type": record_type,
            "records": records,
            "count": len(records),
        }
        return JSONFormatter.format(data)

    @staticmethod
    def format_nameservers(domain: str, whois_ns: List[str], dns_ns: List[str]) -> str:
        """Format nameservers as JSON."""
        data = {"domain": domain, "nameservers": {"whois": whois_ns, "dns": dns_ns}}
        return JSONFormatter.format(data)

    @staticmethod
    def format_all_records(domain: str, records: Dict[str, List[str]]) -> str:
        """Format all DNS records as JSON."""
        data = {"domain": domain, "records": records}
        return JSONFormatter.format(data)


class CSVFormatter:
    """Formats output as CSV."""

    @staticmethod
    def format_records(domain: str, record_type: str, records: List[str]) -> str:
        """Format DNS records as CSV."""
        output = ["domain,record_type,value"]
        for record in records:
            # Escape commas and quotes in values
            escaped = record.replace('"', '""')
            if "," in escaped or '"' in escaped:
                escaped = f'"{escaped}"'
            output.append(f"{domain},{record_type},{escaped}")
        return "\n".join(output)

    @staticmethod
    def format_all_records(domain: str, records: Dict[str, List[str]]) -> str:
        """Format all DNS records as CSV."""
        output = ["domain,record_type,value"]
        for record_type, values in records.items():
            for value in values:
                escaped = value.replace('"', '""')
                if "," in escaped or '"' in escaped:
                    escaped = f'"{escaped}"'
                output.append(f"{domain},{record_type},{escaped}")
        return "\n".join(output)


class YAMLFormatter:
    """Formats output as YAML."""

    @staticmethod
    def format(data: Any) -> str:
        """Format data as YAML."""
        try:
            import yaml

            return yaml.dump(data, default_flow_style=False, allow_unicode=True)
        except ImportError:
            logger.warning("PyYAML not installed, falling back to JSON format")
            return JSONFormatter.format(data)

    @staticmethod
    def format_records(domain: str, record_type: str, records: List[str]) -> str:
        """Format DNS records as YAML."""
        data = {
            "domain": domain,
            "record_type": record_type,
            "records": records,
            "count": len(records),
        }
        return YAMLFormatter.format(data)

    @staticmethod
    def format_all_records(domain: str, records: Dict[str, List[str]]) -> str:
        """Format all DNS records as YAML."""
        data = {"domain": domain, "records": records}
        return YAMLFormatter.format(data)


def get_formatter(
    format_type: str,
) -> Type[Union[TextFormatter, JSONFormatter, CSVFormatter, YAMLFormatter]]:
    """Get formatter for specified format."""
    formatters = {
        "text": TextFormatter,
        "json": JSONFormatter,
        "csv": CSVFormatter,
        "yaml": YAMLFormatter,
    }

    formatter = formatters.get(format_type.lower())
    if not formatter:
        raise ValueError(f"Unknown format: {format_type}")

    return formatter
