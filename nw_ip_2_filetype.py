#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Netwitness Maltego IP to filetype transform
# returns NWFiletype entities

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

ip_entity = sys.argv[1]

field_name = 'filetype'
where_clause = 'ip.dst=%s || ip.src=%s' % (ip_entity, ip_entity)

ret_data = nwmodule.nwValue(0, 0, 100, field_name, 'application/json', where_clause)

json_data = json.loads(ret_data)
results_dic = json_data['results']
fields_list = results_dic['fields']

print trans_header
file_list = []

for dic in fields_list:
    
    id1 = dic['id1']
    id2 = dic['id2']
    flags = dic['flags']
    value = dic['value']
    count = dic['count']
    type_d = dic['type']
    format_d = dic['format']
    
    if value in file_list:
	continue
    else:

        print """       <Entity Type="netwitness.NWFiletype">
	    <Value>%s</Value>
	    <AdditionalFields>
		<Field Name="ip" DisplayName="IP Address">%s</Field>
		<Field Name="metaid1" DisplayName="Meta id1">%s</Field>
		<Field Name="metaid2" DisplayName="Meta id2">%s</Field>
		<Field Name="type" DisplayName="Type">%s</Field>
		<Field Name="count" DisplayName="Count">%s</Field>
	    </AdditionalFields> 
	</Entity>""" % (value, ip_entity, id1, id2, type_d, count)
    
    file_list.append(value)

# Maltego transform XML footer

trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """

print trans_footer    

