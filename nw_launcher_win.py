#!/usr/bin/python

# Maltego transform to launch netwitness on an IP address entity
# Author: David Bressler (@bostonlink)

import sys, urllib, subprocess

ip_entity = sys.argv[1]

where_clause = 'ip.src=%s || ip.dst=%s' % (ip_entity, ip_entity)

base_url = "nw://10.36.129.90/?collection=ISDISNWC&"
params_dic = {}
params_dic['name'] = "Maltego"
params_dic['where'] = where_clause

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
