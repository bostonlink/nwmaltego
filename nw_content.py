#/usr/bin/env python

# Script to download files via the Netwitness REST API using the /sdk/content function
# Author: David Bressler

# Example params: 
#/sdk/content?force-content-type=text/plain&expiry=600&session=15409197308&render=files&where=extention%3Dexe%2Cdll&includeFileTypes=.exe%3B.dll
#render=files&where=extention=exe,dll&includeFileTypes=.exe;.dll

import urllib2, urllib, sys
from lib import  nwmodule

def nwContent(sid, render, where_clause, file_types):

	conf = open('netwitness.conf', 'r')
	config = conf.readlines()
	conf.close()
	
	for line in config:
	
		try:
	    
			if 'NW_CONCENTRATOR' in line:
				conc_list = line.strip().split('=')
				nwa = str(conc_list[1]).lstrip("'").rstrip("'")
		except:

			print 'Check the NW_CONCENTRATOR field in the netwitness.conf file and make sure it is correct'
		
	base_uri = '/sdk/content?'
	params_dic = {}
	params_dic['session'] = sid
	params_dic['render'] = render
	params_dic['where'] = where_clause
	params_dic['includeFileTypes'] = file_types # must be passed like this: .exe;.dll
	
	enc_params = urllib.urlencode(params_dic)
	full_url = nwa + base_uri + enc_params
	print full_url	
	try:
        
		req = urllib2.Request(full_url)
		ret = urllib2.urlopen(req)
		ret_data = ret.read()
		return ret_data
		
	except urllib2.HTTPError as e:
        
		print e
		sys.exit(0)
		

nwmodule.nw_http_auth()

sid = '15409197308'
render = 'files'
where_clause = 'extension=exe,dll'
file_type = '.exe;.dll'

bdata = nwContent(sid, render, where_clause, file_type)

f = open('malware.exe', 'wb')
f.write(bdata)
f.close()

print "Executable file written to current directory!"
