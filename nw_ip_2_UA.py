#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Maltego NW IP to Client Application (User Agent)
# Author: David Bressler (@bostonlink)

import sys
import urllib2, urllib, json

from lib import nwmodule

# Maltego XML Header
trans_header = """<MaltegoMessage>
<MaltegoTransformResponseMessage>
    <Entities>"""

# BASIC HTTP Authentication to NWD

nwmodule.nw_http_auth()

# NW REST API Query amd results

ip_entity = sys.argv[1]
where_clause = 'ip.src=%s || ip.dst=%s' % (ip_entity, ip_entity)
json_data = json.loads(nwmodule.nwValue(0, 0, 10, 'client', 'application/json', where_clause))
ua_list = []

print trans_header
for d in json_data['results']['fields']:
    value = d['value'].decode('ascii')
    # Kind of a hack but hey it works!
    if value in ua_list:
        continue
    else:

        print """       <Entity Type="netwitness.NWUserAgent">
        <Value>%s</Value>
            <AdditionalFields>
                <Field Name="ip" DisplayName="IP Address">%s</Field>
                <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
                <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
                <Field Name="type" DisplayName="Type">%s</Field>
                <Field Name="count" DisplayName="Count">%s</Field>
            </AdditionalFields> 
        </Entity>""" % (value, ip_entity, d['id1'], d['id2'], d['type'], d['count'])
    
    ua_list.append(value)

# Maltego transform XML footer
trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """
print trans_footer