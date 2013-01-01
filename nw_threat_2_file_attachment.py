#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Netwitness Threat to Filename Maltego transform
# Author: David Bressler (@bostonlink)

import sys
import urllib2, urllib, json
from datetime import datetime, timedelta

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

date_t = datetime.today()
tdelta = timedelta(days=1)
diff = date_t - tdelta
diff = "'" + diff.strftime('%Y-%b-%d %H:%M:%S') + "'-'" + date_t.strftime('%Y-%b-%d %H:%M:%S') + "'"

for i in fields:
    if 'ip' in i:
        parse = i.split('=')
        ip = parse[1]
        where_clause = '(time=%s) && risk.warning="%s" && ip.src=%s || ip.dst=%s' % (diff, risk_name, ip, ip)
    else:
        where_clause = '(time=%s) && risk.warning="%s"' % (diff, risk_name)

field_name = 'attachment'
json_data = json.loads(nwmodule.nwValue(0, 0, 25, field_name, 'application/json', where_clause))
file_list = []

# Print the Maltego XML Header
print trans_header
for d in json_data['results']['fields']:
    value = d['value'].decode('ascii')
    if value in file_list:
        continue
    elif value == "<none>":
        pass
    else:
        # Kind of a hack but hey it works!	
        print """       <Entity Type="netwitness.NWFilename">
            <Value>%s</Value>
                <AdditionalFields>
                    <Field Name="risk" DisplayName="Threat Name">%s</Field>
                    <Field Name="ip" DisplayName="IP Address">%s</Field>
                    <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
                    <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
                    <Field Name="type" DisplayName="Type">%s</Field>
                    <Field Name="count" DisplayName="Count">%s</Field>
                </AdditionalFields> 
        </Entity>""" % (value, risk_name, ip, d['id1'], d['id2'], d['type'], d['count'])

    file_list.append(value)

# Maltego transform XML footer
trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """
print trans_footer