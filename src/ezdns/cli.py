"""Command-line interface for ezdns toolkit.

This module implements the CLI using argparse with proper error handling,
logging, and output formatting.
"""

import sys
import argparse
import logging
from typing import Optional

from .config import settings
from .core import DNSResolver, WHOISLookup, get_public_ip
from .utils import (
    TextFormatter,
    get_formatter,
    EZDNSError,
    InvalidDomainError,
    DNSQueryError,
    DNSNoRecordsError,
    WHOISQueryError,
    IPDetectionError,
)

# Configure logging
logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    """Configure logging for the application.

    Args:
        verbose: Enable verbose (DEBUG) logging
        log_file: Optional log file path
    """
    log_level = logging.DEBUG if verbose else getattr(logging, settings.LOG_LEVEL)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_formatter = logging.Formatter(settings.LOG_FORMAT)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    logger.debug('Logging configured')


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='ezdns',
        description='DNS lookup and domain information tool',
        epilog='For more information, visit: https://github.com/errnair/ezdns-toolkit'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {settings.VERSION}'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '-f', '--format',
        choices=['text', 'json', 'csv', 'yaml'],
        default=settings.DEFAULT_OUTPUT_FORMAT,
        help=f'Output format (default: {settings.DEFAULT_OUTPUT_FORMAT})'
    )

    parser.add_argument(
        '--log-file',
        metavar='PATH',
        help='Write logs to file'
    )

    parser.add_argument(
        '-i', '--myip',
        nargs='?',
        const=True,
        help='Get your public WAN IP address'
    )

    parser.add_argument(
        '-ns', '--nameservers',
        metavar='DOMAIN',
        help='Get nameserver records (NS) from both WHOIS and DNS'
    )

    parser.add_argument(
        '-a', '--a-records',
        metavar='DOMAIN',
        dest='a',
        help='Get A records (IPv4 addresses)'
    )

    parser.add_argument(
        '-aaaa', '--aaaa-records',
        metavar='DOMAIN',
        dest='aaaa',
        help='Get AAAA records (IPv6 addresses)'
    )

    parser.add_argument(
        '-mx', '--mx-records',
        metavar='DOMAIN',
        dest='mx',
        help='Get MX records (mail exchange servers)'
    )

    parser.add_argument(
        '-txt', '--txt-records',
        metavar='DOMAIN',
        dest='txt',
        help='Get TXT records'
    )

    parser.add_argument(
        '-cname', '--cname-records',
        metavar='DOMAIN',
        dest='cname',
        help='Get CNAME records (aliases)'
    )

    parser.add_argument(
        '-soa', '--soa-record',
        metavar='DOMAIN',
        dest='soa',
        help='Get SOA record (start of authority)'
    )

    parser.add_argument(
        '-caa', '--caa-records',
        metavar='DOMAIN',
        dest='caa',
        help='Get CAA records (certificate authority authorization)'
    )

    parser.add_argument(
        '-ptr', '--ptr-record',
        metavar='IP',
        dest='ptr',
        help='Get PTR record (reverse DNS lookup)'
    )

    parser.add_argument(
        '-l', '--list',
        metavar='DOMAIN',
        help='Get all DNS records for a domain'
    )

    parser.add_argument(
        '-w', '--whois',
        metavar='DOMAIN',
        help='Get WHOIS information for a domain'
    )

    return parser


def handle_myip(formatter_class) -> int:
    """Handle public IP detection request.

    Args:
        formatter_class: Output formatter class

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        ip_address = get_public_ip()
        print(ip_address)
        return 0
    except IPDetectionError as e:
        logger.error(f'Failed to detect public IP: {e.message}')
        print(f'Error: {e.message}', file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f'Unexpected error: {e}')
        print(f'Error: {e}', file=sys.stderr)
        return 1


def handle_nameservers(domain: str, formatter_class, output_format: str) -> int:
    """Handle nameserver lookup request.

    Args:
        domain: Domain to query
        formatter_class: Output formatter class
        output_format: Output format type

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        dns_resolver = DNSResolver()
        dns_ns = dns_resolver.get_ns_records(domain)

        whois_lookup = WHOISLookup()
        try:
            whois_ns = whois_lookup.get_nameservers(domain)
        except WHOISQueryError:
            logger.warning('WHOIS query failed, showing DNS results only')
            whois_ns = []

        if output_format == 'text':
            output = formatter_class.format_nameservers(whois_ns, dns_ns)
        elif output_format == 'json':
            output = formatter_class.format_nameservers(domain, whois_ns, dns_ns)
        else:
            all_ns = {'WHOIS': whois_ns, 'DNS': dns_ns}
            output = formatter_class.format(all_ns)

        print(output)
        return 0

    except InvalidDomainError as e:
        logger.error(f'Invalid domain: {e.message}')
        print(f'Error: {e.message}', file=sys.stderr)
        return 1
    except DNSNoRecordsError as e:
        logger.info(f'No nameserver records found for {domain}')
        print(f'No NS records found for {domain}')
        return 0
    except DNSQueryError as e:
        logger.error(f'DNS query failed: {e.message}')
        print(f'Error: {e.message}', file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f'Unexpected error: {e}')
        print(f'Error: {e}', file=sys.stderr)
        return 1


def handle_dns_query(domain: str, record_type: str, formatter_class, output_format: str) -> int:
    """Handle generic DNS query request.

    Args:
        domain: Domain to query
        record_type: Type of DNS record
        formatter_class: Output formatter class
        output_format: Output format type

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        dns_resolver = DNSResolver()

        # Get records based on type
        method_map = {
            'A': dns_resolver.get_a_records,
            'AAAA': dns_resolver.get_aaaa_records,
            'MX': dns_resolver.get_mx_records,
            'TXT': dns_resolver.get_txt_records,
            'CNAME': dns_resolver.get_cname_records,
            'SOA': dns_resolver.get_soa_record,
            'CAA': dns_resolver.get_caa_records,
        }

        method = method_map.get(record_type.upper())
        if not method:
            print(f'Error: Unknown record type: {record_type}', file=sys.stderr)
            return 1

        records = method(domain)

        if not isinstance(records, list):
            records = [records] if records else []

        if output_format == 'text':
            title = f'{record_type} Record(s)'
            output = formatter_class.format_list(title, records)
        elif output_format == 'json':
            output = formatter_class.format_records(domain, record_type, records)
        elif output_format == 'csv':
            output = formatter_class.format_records(domain, record_type, records)
        else:  # yaml
            output = formatter_class.format_records(domain, record_type, records)

        print(output)
        return 0

    except InvalidDomainError as e:
        logger.error(f'Invalid domain: {e.message}')
        print(f'Error: {e.message}', file=sys.stderr)
        return 1
    except DNSNoRecordsError as e:
        logger.info(f'No {record_type} records found for {domain}')
        print(f'No {record_type} records found for {domain}')
        return 0
    except DNSQueryError as e:
        logger.error(f'DNS query failed: {e.message}')
        print(f'Error: {e.message}', file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f'Unexpected error: {e}')
        print(f'Error: {e}', file=sys.stderr)
        return 1


def handle_ptr_query(ip_address: str, formatter_class, output_format: str) -> int:
    """Handle PTR (reverse DNS) query request.

    Args:
        ip_address: IP address to query
        formatter_class: Output formatter class
        output_format: Output format type

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        dns_resolver = DNSResolver()
        records = dns_resolver.get_ptr_record(ip_address)

        # Format and print output
        if output_format == 'text':
            output = formatter_class.format_list(f'PTR Record(s) for {ip_address}', records)
        elif output_format == 'json':
            output = formatter_class.format_records(ip_address, 'PTR', records)
        elif output_format == 'csv':
            output = formatter_class.format_records(ip_address, 'PTR', records)
        else:  # yaml
            output = formatter_class.format_records(ip_address, 'PTR', records)

        print(output)
        return 0

    except DNSNoRecordsError:
        logger.info(f'No PTR records found for {ip_address}')
        print(f'No PTR records found for {ip_address}')
        return 0
    except DNSQueryError as e:
        logger.error(f'PTR query failed: {e.message}')
        print(f'Error: {e.message}', file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f'Unexpected error: {e}')
        print(f'Error: {e}', file=sys.stderr)
        return 1


def handle_all_records(domain: str, formatter_class, output_format: str) -> int:
    """Handle request for all DNS records.

    Args:
        domain: Domain to query
        formatter_class: Output formatter class
        output_format: Output format type

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        dns_resolver = DNSResolver()

        dns_ns = []
        whois_ns = []
        try:
            dns_ns = dns_resolver.get_ns_records(domain)
        except (DNSNoRecordsError, DNSQueryError):
            pass

        try:
            whois_lookup = WHOISLookup()
            whois_ns = whois_lookup.get_nameservers(domain)
        except WHOISQueryError:
            pass

        all_records = dns_resolver.get_all_records(domain)

        if output_format == 'text':
            print(formatter_class.format_nameservers(whois_ns, dns_ns))
            print(formatter_class.format_all_records(all_records))
        elif output_format == 'json':
            combined = {
                'domain': domain,
                'nameservers': {'whois': whois_ns, 'dns': dns_ns},
                'records': all_records
            }
            print(formatter_class.format(combined))
        elif output_format == 'csv':
            all_records['WHOIS_NS'] = whois_ns
            all_records['DNS_NS'] = dns_ns
            print(formatter_class.format_all_records(domain, all_records))
        else:  # yaml
            combined = {
                'domain': domain,
                'nameservers': {'whois': whois_ns, 'dns': dns_ns},
                'records': all_records
            }
            print(formatter_class.format(combined))

        return 0

    except InvalidDomainError as e:
        logger.error(f'Invalid domain: {e.message}')
        print(f'Error: {e.message}', file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f'Unexpected error: {e}')
        print(f'Error: {e}', file=sys.stderr)
        return 1


def handle_whois(domain: str, formatter_class, output_format: str) -> int:
    """Handle WHOIS information request.

    Args:
        domain: Domain to query
        formatter_class: Output formatter class
        output_format: Output format type

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        whois_lookup = WHOISLookup()
        whois_data = whois_lookup.query(domain)

        # Format and print output
        if output_format == 'text':
            print(f"\nWHOIS Information for {domain}")
            print("=" * (24 + len(domain)))
            for key, value in whois_data.items():
                if isinstance(value, list):
                    print(f"\n  {key}:")
                    for item in value:
                        print(f"    > {item}")
                else:
                    print(f"  {key}: {value}")
            print()
        else:
            whois_data['domain'] = domain
            print(formatter_class.format(whois_data))

        return 0

    except InvalidDomainError as e:
        logger.error(f'Invalid domain: {e.message}')
        print(f'Error: {e.message}', file=sys.stderr)
        return 1
    except WHOISQueryError as e:
        logger.error(f'WHOIS query failed: {e.message}')
        print(f'Error: {e.message}', file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f'Unexpected error: {e}')
        print(f'Error: {e}', file=sys.stderr)
        return 1


def main() -> int:
    """Main CLI entry point.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = create_parser()

    # If no arguments, print help
    if len(sys.argv) == 1:
        parser.print_help()
        return 1

    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    # Get formatter
    try:
        formatter_class = get_formatter(args.format)
    except ValueError as e:
        print(f'Error: {e}', file=sys.stderr)
        return 1

    # Route to appropriate handler
    try:
        if args.myip:
            return handle_myip(formatter_class)
        elif args.nameservers:
            return handle_nameservers(args.nameservers, formatter_class, args.format)
        elif args.a:
            return handle_dns_query(args.a, 'A', formatter_class, args.format)
        elif args.aaaa:
            return handle_dns_query(args.aaaa, 'AAAA', formatter_class, args.format)
        elif args.mx:
            return handle_dns_query(args.mx, 'MX', formatter_class, args.format)
        elif args.txt:
            return handle_dns_query(args.txt, 'TXT', formatter_class, args.format)
        elif args.cname:
            return handle_dns_query(args.cname, 'CNAME', formatter_class, args.format)
        elif args.soa:
            return handle_dns_query(args.soa, 'SOA', formatter_class, args.format)
        elif args.caa:
            return handle_dns_query(args.caa, 'CAA', formatter_class, args.format)
        elif args.ptr:
            return handle_ptr_query(args.ptr, formatter_class, args.format)
        elif args.list:
            return handle_all_records(args.list, formatter_class, args.format)
        elif args.whois:
            return handle_whois(args.whois, formatter_class, args.format)
        else:
            parser.print_help()
            return 1

    except KeyboardInterrupt:
        print('\n\nInterrupted by user', file=sys.stderr)
        return 130
    except Exception as e:
        logger.exception('Unhandled exception in main')
        print(f'Fatal error: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
