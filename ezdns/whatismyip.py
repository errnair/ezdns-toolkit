#!/usr/bin/env python

import urllib.request
import json

def whatismyip():
    ip_response =  json.loads(urllib.request.urlopen('http://wtfismyip.com/json').read().decode("utf-8"))
    return ip_response["YourFuckingIPAddress"]
