#!/usr/bin/python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Netwitness API script that returns the queryable language definitions of all meta within NW
# Author: David Bressler (@bostonlink)

import urllib2, urllib, nwmodule, json

# Authenticate to the NW Concentrator via HTTP basic auth

nwmodule.nw_http_auth()

ctype = 'application/json'

nw_lang = nwmodule.nwLanguage(ctype)

json_data = json.loads(nw_lang)
results_dic = json_data['results']
fields_list = results_dic['fields']

for dic in fields_list:

    id1 = dic['id1']
    id2 = dic['id2']
    flags = dic['flags']
    value = dic['value']
    count = dic['count']
    type_d = dic['type']
    format_d = dic['format']

    print "Value: %s || Type: %s" % (value, type_d)
