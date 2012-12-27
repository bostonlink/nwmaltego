#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Netwitness Maltego IP Source || IP Destination to Threat transform
# Author: David Bressler (@bostonlink)

import sys
import urllib2, urllib, json

from lib import nwmodule

# Maltego XML Header
trans_header = """<MaltegoMessage>
<MaltegoTransformResponseMessage>
    <Entities>"""

# Authenticate to the NW Concentrator via HTTP basic auth

nwmodule.nw_http_auth()

# NW REST API Query amd results

ip_entity = sys.argv[1]
where_clause = 'ip.src=%s || ip.dst=%s' % (ip_entity, ip_entity)
json_data = json.loads(nwmodule.nwValue(0, 0, 25, 'risk.warning', 'application/json', where_clause))

print trans_header
for d in json_data['results']['fields']:
    # Kind of a hack but hey it works!
    print """	    <Entity Type="netwitness.NWThreat">
        <Value>%s</Value>
            <AdditionalFields>
                <Field Name="ip" DisplayName="IP Address">%s</Field>
                <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
                <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
                <Field Name="type" DisplayName="Type">%s</Field>
                <Field Name="count" DisplayName="Count">%s</Field>
            </AdditionalFields> 
    </Entity>""" % (d['value'].decode('ascii'), ip_entity, d['id1'], d['id2'], d['type'], d['count'])

# Maltego transform XML footer
trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """
print trans_footer