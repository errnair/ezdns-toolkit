#!/usr/bin/env python

import whois
import dns.resolver
import tldextract

def ns(url):
    nameservers = []
    whois_ns = []
    combined_ns = {}

    domain_parts = tldextract.extract(url)
    domain = domain_parts.registered_domain

    whois_obj = whois.whois(domain)
    whois_nslist = whois_obj.name_servers
    whois_nslist = [item.lower() for item in whois_nslist]
    whois_ns = list(dict.fromkeys(whois_nslist))

    nsResolver = dns.resolver.Resolver()
    nsAnswers = nsResolver.query(domain, "NS")
    for rdata in nsAnswers:
        nameservers.append(str(rdata))

    combined_ns['whois'] = whois_ns
    combined_ns['ns'] = nameservers
    return(combined_ns)

def mx(url):
    mxservers = []

    domain_parts = tldextract.extract(url)
    domain = domain_parts.registered_domain

    mxResolver = dns.resolver.Resolver()
    mxAnswers = mxResolver.query(domain, "MX")
    for rdata in mxAnswers:
        mxservers.append(str(rdata))
    return(mxservers)

def a(url):
    aRecords = []

    domain_parts = tldextract.extract(url)
    domain = domain_parts.registered_domain

    aResolver = dns.resolver.Resolver()
    aAnswers = aResolver.query(domain, "A")
    for rdata in aAnswers:
        aRecords.append(str(rdata))
    return(aRecords)

def txt(url):
    txtservers = []

    domain_parts = tldextract.extract(url)
    domain = domain_parts.registered_domain

    txtResolver = dns.resolver.Resolver()
    txtAnswers = txtResolver.query(domain, "TXT")
    for rdata in txtAnswers:
        txtservers.append(str(rdata))
    return(txtservers)
