#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Netwitness Threat to Filetype
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

risk_name = sys.argv[1]
fields = sys.argv[2].split('#')
for i in fields:
    if 'ip' in i:
        parse = i.split('=')
        ip = parse[1]
        where_clause = 'risk.warning="%s" && ip.src=%s || ip.dst=%s' % (risk_name, ip, ip)
    else:
        where_clause = 'risk.warning="%s"' % (risk_name)

field_name = 'filetype'
json_data = json.loads(nwmodule.nwValue(0, 0, 25, field_name, 'application/json', where_clause))
file_list = []

print trans_header
for d in json_data['results']['fields']:
    if value in file_list:
        continue
    else:
	# Kind of a hack but hey it works!
        print """       <Entity Type="netwitness.NWFiletype">
	    <Value>%s</Value>
	    <AdditionalFields>
            <Field Name="risk_name" DisplayName="Risk Name">%s</Field>
            <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
            <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
            <Field Name="type" DisplayName="Type">%s</Field>
            <Field Name="count" DisplayName="Count">%s</Field>
	    </AdditionalFields> 
	</Entity>""" % (d['value'].decode('ascii'), risk_name, d['id1'], d['id2'], d['type'], d['count'])
    
    file_list.append(value)

# Maltego transform XML footer
trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """
print trans_footer