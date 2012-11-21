#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Maltego NW Threat NO IP to Client Application (User Agent)
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

# NW REST API Query

risk_name = sys.argv[1]

where_clause = 'risk.warning="%s"' % (risk_name)

nwquery = nwmodule.nwValue(0, 0, 20, 'client', 'application/json', where_clause)
json_data = json.loads(nwquery)
results_dic = json_data['results']
fields_list = results_dic['fields']

print trans_header

ip_list = []

for dic in fields_list:

    id1 = dic['id1']
    id2 = dic['id2']
    flags = dic['flags']
    value = dic['value']
    count = dic['count']
    type_d = dic['type']
    format_d = dic['format']
    group = dic['group'] 

    if value in ip_list:
	continue
    else:
	# Kind of a hack but hey it works!
        print """       <Entity Type="netwitness.NWUserAgent">
	        <Value>%s</Value>
	        <AdditionalFields>
		  <Field Name="threat" DisplayName="Threat Name">%s</Field>
		  <Field Name="ip" DisplayName="IP Address">%s</Field>
		  <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
		  <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
		  <Field Name="type" DisplayName="Type">%s</Field>
		  <Field Name="count" DisplayName="Count">%s</Field>
		</AdditionalFields> 
	   </Entity>""" % (value, risk_name, ip, id1, id2, type_d, count)
    
    ip_list.append(value)

# Maltego transform XML footer

trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """

print trans_footer

