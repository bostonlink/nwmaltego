#!/usr/bin/python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Netwitness API script that returns the queryable language definitions of all meta within NW
# Author: David Bressler (@bostonlink)

import sys
import urllib2, urllib, json

from lib import nwmodule

# Authenticate to the NW Concentrator via HTTP basic auth

nwmodule.nw_http_auth()

ctype = 'application/json'
json_data = json.loads(nwmodule.nwLanguage(ctype))
for d in json_data['results']['fields']:
    print "Value: %s || Type: %s" % (d['value'].decode('ascii'), d['type'])