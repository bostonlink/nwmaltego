#!/usr/bin/python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Maltego transform to launch netwitness on an IP address entity
# Author: David Bressler (@bostonlink)

import sys, urllib, subprocess

ip_entity = sys.argv[1]

where_clause = 'ip.src=%s || ip.dst=%s' % (ip_entity, ip_entity)

conf = open('netwitness.conf', 'r')
config = conf.readlines()
conf.close()

for line in config:

    if 'CONCENTRATOR_IP' in line:
    	split = line.strip().split('=')
    	nwc_ip = split[1].lstrip("'").rstrip("'")
    elif 'COLLECTION_NAME' in line:
    	split = line.strip().split('=')
    	col_name = split[1].lstrip("'").rstrip("'")

base_url = "nw://%s/?collection=%s&" % (nwc_ip, col_name)
params_dic = {'name': "Maltego Query", 'where': where_clause}
enc_uri = urllib.urlencode(params_dic)
full_url = base_url + enc_uri
nw_path = "C:\Program Files\NetWitness\NetWitness 9.7\Investigator\NwInvestigator.exe"

# print full_url

print """<MaltegoMessage>
<MaltegoTransformResponseMessage>
        <Entities>
        </Entities>
</MaltegoTransformResponseMessage>
</MaltegoMessage> """

subprocess.Popen([nw_path, full_url], stdout=subprocess.PIPE, shell=False)
sys.exit(0)