### ezdns-toolkit - an easy-to-use DNS toolkit for humans.

#### Requirements

- Python 3.x

#### Purpose

The purpose of this script is to list/display the DNS-related and domain-related information for a domain, in a simple, easy-to-understand format.  
The script can also accept arguments for various tasks like:


- Check and display your WAN IP.
- List the Nameservers for a domain, from both the Webhosting Provider (NS Records) and the Domain Registrar (WHOIS NS).
- List the A record of a domain.
- List the MX record of a domain.
- List the TXT records of a domain.
- List all the DNS records of a domain.

```
$ python main.py --help
usage: main.py [-h] [-i [MYIP]] [-ns NS] [-a A] [-mx MX] [-txt TXT] [-l LIST]

optional arguments:
  -h, --help            show this help message and exit
  -i [MYIP], --myip [MYIP]
                        Get your WAN IP
  -ns NS, --NS NS       Get a domain's NS records.
  -a A, --A A           Get a domain's A record.
  -mx MX, --MX MX       Get a domain's MX record.
  -txt TXT, --TXT TXT   Get a domain's TXT record(s).
  -l LIST, --list LIST  Get all the DNS record(s) of a domain.
```

#### Usage

- What is my IP (WAN IP)
```
$ python main.py --myip
XXX.XXX.XXX.XXX

$ python main.py -i
XXX.XXX.XXX.XXX
```

- Display the Nameservers
```
$ python main.py -ns stackoverflow.com

Nameservers
===========
  > WHOIS NS
        ns-1033.awsdns-01.org
        ns-358.awsdns-44.com
        ns-cloud-e1.googledomains.com
        ns-cloud-e2.googledomains.com
  > DOMAIN NS
        ns-358.awsdns-44.com.
        ns-1033.awsdns-01.org.
        ns-cloud-e1.googledomains.com.
        ns-cloud-e2.googledomains.com.
```
