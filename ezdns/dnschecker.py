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
        nameservers.append(rdata)

    combined_ns['whois'] = whois_ns
    combined_ns['ns'] = nameservers
    return(combined_ns)
