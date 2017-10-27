#!/usr/bin/env python

import argparse
import sys
from ezdns import *

def main():
 
    cli_argparser = argparse.ArgumentParser(description='')
    cli_argparser.add_argument('-ip', '--whatismyip', nargs='?', const=1, help="Get your WAN IP", required=False)
    cli_argparser.add_argument('-ns', '--NS', help="Get a domain's NS records.", required=False)
    cli_argparser.add_argument('-a', '--A', help="Get a domain's A record.", required=False)
    cli_args = cli_argparser.parse_args()

    if (cli_args.NS and cli_args.A):
        print ("print A and NS")
    elif (cli_args.whatismyip):
        print (whatismyip.whatismyip())
    elif (cli_args.NS):
        print ("print NS")
    elif (cli_args.A):
        print ("print A")
    else:
        print ("Default")

if __name__ == '__main__':
    sys.exit(main())
