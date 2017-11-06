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

```python
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

1. What is my IP (WAN IP)
```
$ python main.py --myip
XXX.XXX.XXX.XXX

$ python main.py -i
XXX.XXX.XXX.XXX
```

2. Display the Nameserver Records
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
  
3. Display the A Records
```
$ python main.py -a stackoverflow.com

A Record(s)
===========
  > 151.101.1.69
  > 151.101.65.69
  > 151.101.129.69
  > 151.101.193.69
```
  
4. Display the MX Records
```
$ python main.py -mx stackoverflow.com

MX Record(s)
============
  > 1 aspmx.l.google.com.
  > 5 alt1.aspmx.l.google.com.
  > 5 alt2.aspmx.l.google.com.
  > 10 alt3.aspmx.l.google.com.
  > 10 alt4.aspmx.l.google.com.
  
$ python main.py -mx muchbits.com

MX Record(s)
============
  > 0 muchbits.com.
```
  
5. Display the TXT Records
```
$ python main.py -txt google.com

TXT Record(s)
=============
  > "v=spf1 include:_spf.google.com ~all"

$ python main.py -txt stackoverflow.com

TXT Record(s)
=============
  > "MS=ms52592611"
  > "google-site-verification=o3EMam8yBGo1yEjyybIiZcOunGHOQKpo8JmOtp9n1BU"
  > "google-site-verification=rdWtMbplKjbRHGr2dNONfwkqithlUvjr3u6i8QEz_mo"
  > "v=spf1 ip4:198.252.206.0/24 ip4:192.111.0.0/24 include:_spf.google.com include:mailgun.org ip4:64.34.80.172 include:mail.zendesk.com include:servers.mcsv.net include:sendgrid.net ~all"
```
  
6. Display all the DNS Records
```
$ python main.py -l stackoverflow.com

>> Nameservers
   ===========
  > WHOIS NS
        ns-1033.awsdns-01.org
        ns-358.awsdns-44.com
        ns-cloud-e1.googledomains.com
        ns-cloud-e2.googledomains.com
  > DOMAIN NS
        ns-1033.awsdns-01.org.
        ns-358.awsdns-44.com.
        ns-cloud-e1.googledomains.com.
        ns-cloud-e2.googledomains.com.

>> A Record(s)
   ===========
  > 151.101.1.69
  > 151.101.65.69
  > 151.101.129.69
  > 151.101.193.69

>> MX Record(s)
   ============
  > 1 aspmx.l.google.com.
  > 5 alt1.aspmx.l.google.com.
  > 5 alt2.aspmx.l.google.com.
  > 10 alt3.aspmx.l.google.com.
  > 10 alt4.aspmx.l.google.com.

>> TXT Record(s)
   =============
  > "MS=ms52592611"
  > "google-site-verification=o3EMam8yBGo1yEjyybIiZcOunGHOQKpo8JmOtp9n1BU"
  > "google-site-verification=rdWtMbplKjbRHGr2dNONfwkqithlUvjr3u6i8QEz_mo"
  > "v=spf1 ip4:198.252.206.0/24 ip4:192.111.0.0/24 include:_spf.google.com include:mailgun.org ip4:64.34.80.172 include:mail.zendesk.com include:servers.mcsv.net include:sendgrid.net ~all"
```
