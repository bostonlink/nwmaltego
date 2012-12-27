#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Netwitness FileType to threat maltego transform
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

file_type = sys.argv[1]
field_name = 'risk.warning'
where_clause = 'filetype="%s"' % file_type
json_data = json.loads(nwmodule.nwValue(0, 0, 25, field_name, 'application/json', where_clause))
file_list = []

print trans_header
for d in json_data['results']['fields']:
    # Kind of a hack but hey it works!    
    if value in file_list:
        continue
    else:
        print """       <Entity Type="netwitness.NWThreatNOIP">
        <Value>%s</Value>
            <AdditionalFields>
                <Field Name="filetype" DisplayName="File Type">%s</Field>
                <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
                <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
                <Field Name="type" DisplayName="Type">%s</Field>
                <Field Name="count" DisplayName="Count">%s</Field>
            </AdditionalFields> 
	    </Entity>""" % (d['value'].decode('ascii'), file_type, d['id1'], d['id2'], d['type'], d['count'])
    
    file_list.append(value)

# Maltego transform XML footer

trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """

print trans_footer