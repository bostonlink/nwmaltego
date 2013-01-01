#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Maltego NW Threat to  all IP addresses transform
# Author: David Bressler (@bostonlink)

import sys
import urllib2, urllib, json
from datetime import datetime, timedelta

from lib import nwmodule

# Maltego XML Header
trans_header = """<MaltegoMessage>
<MaltegoTransformResponseMessage>
    <Entities>"""

# BASIC HTTP Authentication to NWD

nwmodule.nw_http_auth()

# NW REST API Query amd results

risk_name = sys.argv[1]

date_t = datetime.today()
tdelta = timedelta(days=1)
diff = date_t - tdelta
diff = "'" + diff.strftime('%Y-%b-%d %H:%M:%S') + "'-'" + date_t.strftime('%Y-%b-%d %H:%M:%S') + "'"

threat_ip_all = 'select ip.dst,ip.src where (time=%s) && risk.warning="%s"' % (diff, risk_name)
json_data = json.loads(nwmodule.nwQuery(0, 0, threat_ip_all, 'application/json', 10))
ip_list = []

print trans_header
for d in json_data['results']['fields']:
    value = d['value'].decode('ascii')
    if value in ip_list:
        continue
    else:
	# Kind of a hack but hey it works!
        print """       <Entity Type="maltego.IPv4Address">
	        <Value>%s</Value>
	        <AdditionalFields>
                <Field Name="threat" DisplayName="Threat Name">%s</Field>
                <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
                <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
                <Field Name="type" DisplayName="Type">%s</Field>
                <Field Name="count" DisplayName="Count">%s</Field>
            </AdditionalFields> 
	   </Entity>""" % (value, risk_name, d['id1'], d['id2'], d['type'], d['count'])
    
    ip_list.append(value)

# Maltego transform XML footer
trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """
print trans_footer