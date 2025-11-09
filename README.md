# ezdns-toolkit

DNS lookup tool for querying records, WHOIS information, and network diagnostics.

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE.md)

## Features

- Query all DNS record types (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR)
- WHOIS information extraction
- Public IP detection
- Multiple output formats (JSON, CSV, YAML, text)
- Input validation and HTTPS-only connections

## Installation

```bash
pip install ezdns-toolkit
```

Or install from source:

```bash
git clone https://github.com/errnair/ezdns-toolkit.git
cd ezdns-toolkit
pip install -e .
```

Development setup:

```bash
pip install -e ".[dev]"
```

Requires Python 3.8 or higher.

## Quick Start

```bash
# Get your public IP
ezdns --myip

# Query DNS records
ezdns -a example.com
ezdns --mx example.com
ezdns --txt example.com

# Get all records
ezdns --list example.com

# Export as JSON
ezdns -a example.com --format json

# WHOIS lookup
ezdns --whois example.com
```

## Usage

### DNS Queries

```bash
# A records (IPv4)
$ ezdns -a example.com
93.184.216.34

# AAAA records (IPv6)
$ ezdns --aaaa example.com
2606:2800:220:1:248:1893:25c8:1946

# MX records (mail servers)
$ ezdns --mx example.com
10 mail.example.com.

# TXT records (SPF, DKIM, etc.)
$ ezdns --txt example.com
"v=spf1 mx -all"

# Nameservers (WHOIS + DNS)
$ ezdns --nameservers example.com

Nameservers
===========
  > WHOIS NS
        ns1.example.com
  > DOMAIN NS
        ns1.example.com.

# Reverse DNS
$ ezdns --ptr 93.184.216.34
example.com.
```

### Output Formats

```bash
# JSON
$ ezdns -a example.com --format json
{
  "domain": "example.com",
  "record_type": "A",
  "records": ["93.184.216.34"]
}

# CSV
$ ezdns --list example.com --format csv > records.csv

# YAML
$ ezdns -a example.com --format yaml
```

### Python Library

```python
from ezdns import DNSResolver, get_public_ip

# DNS queries
resolver = DNSResolver()
a_records = resolver.get_a_records('example.com')
mx_records = resolver.get_mx_records('example.com')
all_records = resolver.get_all_records('example.com')

# WHOIS
from ezdns import get_whois_info
whois_data = get_whois_info('example.com')

# Public IP
my_ip = get_public_ip()
```

Error handling:

```python
from ezdns import DNSResolver, DNSQueryError, InvalidDomainError

resolver = DNSResolver()
try:
    records = resolver.get_a_records('example.com')
except InvalidDomainError as e:
    print(f'Invalid domain: {e.message}')
except DNSQueryError as e:
    print(f'Query failed: {e.message}')
```

Custom configuration:

```python
# Use specific DNS servers with custom timeout
resolver = DNSResolver(
    timeout=10.0,
    nameservers=['8.8.8.8', '8.8.4.4']
)
```

## Available DNS Record Types

- **A**: IPv4 addresses
- **AAAA**: IPv6 addresses
- **MX**: Mail exchange servers
- **TXT**: Text records (SPF, DKIM, DMARC)
- **NS**: Nameservers
- **CNAME**: Canonical name aliases
- **SOA**: Start of authority
- **CAA**: Certificate authority authorization
- **PTR**: Reverse DNS lookup

## Configuration

Set environment variables:

```bash
export EZDNS_DNS_TIMEOUT=10.0
export EZDNS_VERBOSE=true
export EZDNS_OUTPUT_FORMAT=json
```

## Command-Line Options

```
usage: ezdns [-h] [--version] [-v] [-f {text,json,csv,yaml}]
             [-i [MYIP]] [-ns NS] [-a A] [-aaaa AAAA] [-mx MX]
             [-txt TXT] [-cname CNAME] [-soa SOA] [-caa CAA]
             [-ptr PTR] [-l LIST] [-w WHOIS]

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         enable verbose output
  -f, --format          output format (text, json, csv, yaml)
  -i, --myip            get your public IP address
  -ns, --nameservers    get nameserver records
  -a, --a-records       get A records
  -aaaa, --aaaa-records get AAAA records
  -mx, --mx-records     get MX records
  -txt, --txt-records   get TXT records
  -cname                get CNAME records
  -soa                  get SOA record
  -caa                  get CAA records
  -ptr                  reverse DNS lookup
  -l, --list            get all DNS records
  -w, --whois           get WHOIS information
```

## Development

Run tests:

```bash
make test
make test-coverage
```

Code quality:

```bash
make lint
make format
```

Build package:

```bash
make build
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

GNU General Public License v3.0 - see [LICENSE.md](LICENSE.md)

## Links

- [Issue Tracker](https://github.com/errnair/ezdns-toolkit/issues)
- [Changelog](CHANGELOG.md)
