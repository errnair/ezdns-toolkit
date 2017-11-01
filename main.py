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

    if (cli_args.NS and cli_args.A):
        print (dnschecker.ns(cli_args.NS))
        print (dnschecker.a(cli_args.A))
    elif (cli_args.myip):
        print (whatismyip.whatismyip())
    elif (cli_args.NS):
        print (dnschecker.ns(cli_args.NS))
    elif (cli_args.A):
        print (dnschecker.a(cli_args.A))
    elif (cli_args.MX):
        print (dnschecker.mx(cli_args.MX))
    elif (cli_args.TXT):
        print (dnschecker.txt(cli_args.TXT))
    elif (cli_args.list):
        print (dnschecker.ns(cli_args.list))
        print (dnschecker.a(cli_args.list))
        print (dnschecker.mx(cli_args.list))
        print (dnschecker.txt(cli_args.list))
    else:
        print ("Default")

if __name__ == '__main__':
    sys.exit(main())
