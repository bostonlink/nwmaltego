#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Author: David Bressler
# Netwitness python functions to interface with the NW REST API

import urllib2, urllib, sys

# HTTP Basic Authentication to NW REST API
 
def nw_http_auth():

    """Authenticates to the NW REST API via HTTP Basic authentication"""

    conf = open('netwitness.conf', 'r')
    config = conf.readlines()
    conf.close()

    for line in config:
	
	try:

	    if 'USERNAME' in line:
		usr_list = line.strip().split('=')
		nwusr = str(usr_list[1]).lstrip("'").rstrip("'")

	    elif 'PASSWORD' in line:
		passwd_list = line.strip().split('=')
		nwpass = str(passwd_list[1]).lstrip("'").rstrip("'")

	    elif 'NW_CONCENTRATOR' in line:
		conc_list = line.strip().split('=')
		nwa = str(conc_list[1]).lstrip("'").rstrip("'")
	
	except:
	    
	    return 'Authentication has failed to NW please check your netwitness.conf file'
    
    auth_handler = urllib2.HTTPBasicAuthHandler()
    auth_handler.add_password(realm = 'NetWitness',
                              uri = nwa,
                              user = nwusr,
                              passwd = nwpass )

    opener = urllib2.build_opener(auth_handler)
    urllib2.install_opener(opener)

# Function builds full URL for NW REST API Query and returns the results
#
# Sample query examples that can be passed to the nwQuery module
# query = 'select service,ip.src,country.dst where service=80'
# pe_java_query = 'select filename,ip.src,ip.dst where filetype="x86 pe","java_jar"'
# all_pe_query = 'select filename,ip.src,ip.dst where filetype="x86 pe"'
# ip_exe_query = 'select filename,ip.src,ip.dst where filetype="x86 pe","java_jar" && (ip.src=1.1.1.1)'

def nwQuery(id1, id2, query_string, cType, size):

    """ Queries the NW REST API and returns the results 
    Example query that would be passed to the function in the query_string variable:
    query = 'select service,ip.src,country.dst where service=80'"""
    
    conf = open('netwitness.conf', 'r')
    config = conf.readlines()
    conf.close()

    for line in config:

	try:
	    
	    if 'NW_CONCENTRATOR' in line:
		conc_list = line.strip().split('=')
                nwa = str(conc_list[1]).lstrip("'").rstrip("'")
	except:

	    return 'Check the NW_CONCENTRATOR field in the netwitness.conf file and make sur eit is correct'

    base_uri = "/sdk?msg=query&"
    params_dic = {}
    params_dic['force-content-type'] = cType
    params_dic['expiry'] = 600
    params_dic['id1'] = id1
    params_dic['id2'] = id2
    params_dic['size'] = size
    params_dic['query'] = query_string

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params
    
    try:
        
        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()
        return ret_data
    
    except urllib2.HTTPError as e:
        
        print e
	sys.exit(0)

#  Retrieves the meta id range for the session range

def nwSession(id1, id2, cType):
    
    """ Returns the meta id for a specific session range.  
    If id1=0 and id2=0 it returns the meta id range for all data """

    conf = open('netwitness.conf', 'r')
    config = conf.readlines()
    conf.close()

    for line in config:

        try:
            
            if 'NW_CONCENTRATOR' in line:
                conc_list = line.strip().split('=')
                nwa = str(conc_list[1]).lstrip("'").rstrip("'")
    
        except:

            print 'Check the NW_CONCENTRATOR field in the netwitness.conf file and make sur eit is correct'

    base_uri = "/sdk?msg=session&"
    params_dic = {}
    params_dic['force-content-type'] = cType
    params_dic['expiry'] = 600
    params_dic['id1'] = id1
    params_dic['id2'] = id2

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params
    
    try:
        
        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()
        return ret_data
    
    except urllib2.HTTPError as e:
        
        print e
	sys.exit(0)

# values: Performs a query and returns the matching values for a report
# example: nwValue(nwa, 0, 0, 100, 'risk.warning', 'text/plain')

def nwValue(id1, id2, size, fieldname, cType, where=''):

    """ Returns a values associated with a meta type.
    If the where_clause is used, you can return specific values of a certain type.
    For example:
    
    nwmodule.nwValue(nwa, 0, 0, 100, 'risk.warning', 'text/plain')
    
    returns all values associated with the risk.warning meta type."""

    conf = open('netwitness.conf', 'r')
    config = conf.readlines()
    conf.close()

    for line in config:

        try:
            
            if 'NW_CONCENTRATOR' in line:
                conc_list = line.strip().split('=')
                nwa = str(conc_list[1]).lstrip("'").rstrip("'")
    
        except:

            print 'Check the NW_CONCENTRATOR field in the netwitness.conf file and make sur eit is correct'

    base_uri = "/sdk?msg=values&"
    params_dic = {}
    params_dic['force-content-type'] = cType
    params_dic['expiry'] = 600
    params_dic['id1'] = id1
    params_dic['id2'] = id2
    params_dic['size'] = size
    params_dic['fieldName'] = fieldname
    params_dic['where'] = where

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params
    
    try:
        
        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()
        return ret_data
    
    except urllib2.HTTPError as e:
        
        print e
	sys.exit(0)

# timeline: Returns the count of sessions/size/packets in discrete time intervals
# example: 

def nwTimeline(time1, time2, size, cType, where=''):

    """ Returns the count of sessions/size/packets in discrete time intervals """
    
    conf = open('netwitness.conf', 'r')
    config = conf.readlines()
    conf.close()

    for line in config:

        try:
            
            if 'NW_CONCENTRATOR' in line:
                conc_list = line.strip().split('=')
                nwa = str(conc_list[1]).lstrip("'").rstrip("'")
    
        except:

            print 'Check the NW_CONCENTRATOR field in the netwitness.conf file and make sur eit is correct'
    
    base_uri = "/sdk?msg=timeline&"
    params_dic = {}
    params_dic['force-content-type'] = cType
    params_dic['expiry'] = 600
    params_dic['time1'] = time1
    params_dic['time2'] = time2
    params_dic['size'] = size
    params_dic['where'] = where

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params

    try:
        
        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()
        return ret_data
    
    except urllib2.HTTPError as e:
        
        print e
	sys.exit(0)

# Returns all queryable fields and definitions wtihin NW

def nwLanguage(cType):

    """ Returns all field types and definitions you can query wtihin NW """

    conf = open('netwitness.conf', 'r')
    config = conf.readlines()
    conf.close()

    for line in config:

        try:
            
            if 'NW_CONCENTRATOR' in line:
                conc_list = line.strip().split('=')
                nwa = str(conc_list[1]).lstrip("'").rstrip("'")
    
        except:

            print 'Check the NW_CONCENTRATOR field in the netwitness.conf file and make sur eit is correct'    

    base_uri = "/sdk?msg=language&"
    params_dic = {}
    params_dic['force-content-type'] = cType
    params_dic['expiry'] = 600
    params_dic['size'] = 200

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params

    try:
        
        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        ret_data = ret.read()
        return ret_data
    
    except urllib2.HTTPError as e:
        
        print e
	sys.exit(0)
