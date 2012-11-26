#!/usr/bin/env python

# Maltego Phrase to NW Threat
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

risk_phrase = sys.argv[1]

threat_ip_dst = 'select risk.warning where risk.warning contains %s' % risk_phrase

nwquery = nwmodule.nwQuery(0, 0, threat_ip_dst, 'application/json', 25)
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

	if '&' in value:
            new_value = value.replace('&', '%amp;')
            print """       <Entity Type="netwitness.NWThreatNOIP">
                <Value>%s</Value>
                <AdditionalFields>
                    <Field Name="phrase" DisplayName="Phrase">%s</Field>
                    <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
                    <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
                    <Field Name="type" DisplayName="Type">%s</Field>
                    <Field Name="count" DisplayName="Count">%s</Field>
                </AdditionalFields> 
            </Entity>""" % (new_value, risk_phrase, id1, id2, type_d, count)

        else:

	    print """       <Entity Type="netwitness.NWThreatNOIP">
		<Value>%s</Value>
		<AdditionalFields>
		    <Field Name="phrase" DisplayName="Phrase">%s</Field>
		    <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
		    <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
		    <Field Name="type" DisplayName="Type">%s</Field>
		    <Field Name="count" DisplayName="Count">%s</Field>
		</AdditionalFields> 
	    </Entity>""" % (value, risk_phrase, id1, id2, type_d, count)
    
    ip_list.append(value)

# Maltego transform XML footer

trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """

print trans_footer

