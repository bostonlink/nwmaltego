#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

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

# NW REST API Query amd results

risk_phrase = sys.argv[1]
threat_ip_dst = 'select risk.warning where risk.warning contains %s' % risk_phrase
json_data = json.loads(nwmodule.nwQuery(0, 0, threat_ip_dst, 'application/json', 25))
ip_list = []

print trans_header
for d in json_data['results']['fields']:
    value = d['value'].decode('ascii')
    if value in ip_list:
        continue
    else:
        # Kind of a hack but hey it works!
        print """       <Entity Type="netwitness.NWThreatNOIP">
                <Value>%s</Value>
                <AdditionalFields>
                    <Field Name="phrase" DisplayName="Phrase">%s</Field>
                    <Field Name="metaid1" DisplayName="Meta id1">%s</Field>
                    <Field Name="metaid2" DisplayName="Meta id2">%s</Field>
                    <Field Name="type" DisplayName="Type">%s</Field>
                    <Field Name="count" DisplayName="Count">%s</Field>
                </AdditionalFields> 
        </Entity>""" % (value, risk_phrase, d['id1'], d['id2'], d['type'], d['count'])

    ip_list.append(value)

# Maltego transform XML footer

trans_footer = """  </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """
print trans_footer