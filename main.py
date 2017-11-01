#!/usr/bin/env python

import argparse
import sys
from ezdns import *

def main():
 
    cli_argparser = argparse.ArgumentParser(description='')
    cli_argparser.add_argument('-i', '--myip', nargs='?', const=1, help="Get your WAN IP", required=False)
    cli_argparser.add_argument('-ns', '--NS', help="Get a domain's NS records.", required=False)
    cli_argparser.add_argument('-a', '--A', help="Get a domain's A record.", required=False)
    cli_argparser.add_argument('-mx', '--MX', help="Get a domain's MX record.", required=False)
    cli_argparser.add_argument('-txt', '--TXT', help="Get a domain's TXT record(s).", required=False)
    cli_argparser.add_argument('-l', '--list', help="Get all the DNS record(s) of a domain.", required=False)
    cli_args = cli_argparser.parse_args()

    if (cli_args.NS):
        ns_dict = dnschecker.ns(cli_args.NS)
        print ("\nNameservers\n===========")
        for key in ns_dict:
            print ("  > " + key)
            for item in (ns_dict[key]):
                print ("\t" + item)
        print ("\n")
    elif (cli_args.A):
        print ("\nA Record(s)\n===========")
        for item in dnschecker.a(cli_args.A):
            print ("  > " + item)
        print ("\n")
    elif (cli_args.MX):
        print ("\nMX Record(s)\n============")
        for item in dnschecker.mx(cli_args.MX):
            print ("  > " + item)
        print ("\n")
    elif (cli_args.TXT):
        print ("\nTXT Record(s)\n=============")
        for item in dnschecker.txt(cli_args.TXT):
            print ("  > " + item)
        print ("\n")
    elif (cli_args.list):
        ns_dict = dnschecker.ns(cli_args.list)
        print ("\n>> Nameservers\n   ===========")
        for key in ns_dict:
            print ("  > " + key)
            for item in (ns_dict[key]):
                print ("\t" + item)
        print ("\n>> A Record(s)\n   ===========")
        for item in dnschecker.a(cli_args.list):
            print ("  > " + item)
        print ("\n>> MX Record(s)\n   ============")
        for item in dnschecker.mx(cli_args.list):
            print ("  > " + item)
        print ("\n>> TXT Record(s)\n   =============")
        for item in dnschecker.txt(cli_args.list):
            print ("  > " + item)
    elif (cli_args.myip):
        print (whatismyip.whatismyip())
    else:
        print ("Default")

if __name__ == '__main__':
    sys.exit(main())
