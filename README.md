NWMaltego
==========

Author: David Bressler (@bostonlink)

About
------

NWMaltego is a multi-platform python project that integrates Netwitness and Maltego together.  It allows for an analyst to graphically map Netwitness data within Maltego.  It includes several new entities and multiple transforms to pull data from Netwitness.

NWmodule.py
-----------

nwmodule.py is a python module I wrote that interfaces with the Netwitness REST API.  All Maltego transforms are dependent on this module and functions within it.  It must ne within the directory that contains the Maltego transforms.

Netwitness.conf
----------------

The netwitness.conf file holds data about the netwitness environment, user credentials, and the location for an output directory where the file extractor transform will save an exracted file from a Netwitness session.

Maltego Transforms
--------------------

Listing of all current Netwitness Maltego transforms and the filename and entity they are associated wtih

maltego.IPv4Address (Entity)<br/>

netwitness.NWIPDsttoThreat - nw_ip_dst_threat.py  <br/>
netwitness.NWIPSourcetoThreat - nw_ip_src_threat.py  <br/>
netwitness.NWIPSRCandDSTtoThreat - nw_ipsrc_dst_threat.py <br/>
netwitness.NWIPtoFileType - nw_ip_2_filetype.py<br/>
netwitness.NWIPtoFilename - nw_ip_2_filename.py<br/>
netwitness.NWIPdestinationtoIPSource - nw_ipdst_2_ip_src.py<br/>
netwitness.NWIPSourcetoIPDestination - nw_ipsrc_2_ip_dst.py<br/>
netwitness.NWIPtoUserAgent - nw_ip_2_UA.py<br/>
netwitness.NWIPtoHostnameAlias - nw_ip_2_hostname_alias.py<br/>
netwitness.LaunchNetwitness - nw_launcher_win.py (Windows Only Transform)<br/>

maltego.Phrase (Entity)<br/>

netwitness.NWPhrasetoThreat - nw_phrase_2_threat.py<br/>

netwitness.NWThreatNOIP (Entity)<br/>
    
netwitness.NWThreatNoIPtoAllIPAddresses - nw_threat_2_ip_all.py<br/>
netwitness.NWThreatNOIPtoFilename - nw_threat_2_filename.py<br/>
netwitness.NWThreatNOIPtoFileAttachment - nw_threat_no_ip_2_file_attachment.py<br/>
netwitness.NWThreatNoIPtoIPSrc - nw_threat_noip_2_ip_src.py<br/>
netwitness.NWThreatNoIPtoIPDst - nw_threat_noip_2_ip_dst.py<br/>
netwitness.NWThreatNOIPtoUserAgent - nw_threat_no_ip_2_UA.py<br/>

netwitness.NWThreat (Entity)<br/>

netwitness.NWThreattoIPDestination - nw_threat_2_ip_dst.py<br/>
netwitness.NWThreattoIPSource - nw_threat_2_ip_src.py<br/>
netwitness.NWThreattoFiletype - nw_threat_2_filetype.py<br/>
netwitness.NWThreattoFilename - nw_threat_2_filename.py<br/>
netwitness.NWThreattoFileAttachment - nw_threat_2_file_attachment.py<br/>
netwitness.NWThreattoUserAgent - nw_threat_2_UA.py<br/>
netwitness.NWThreattoIPall - nw_threat_2_ip_all.py<br/>

netwitness.NWFiletype (Entity)<br/>

netwitness.NWFiltypetoThreat - nw_filetype_2_threat.py<br/>
netwitness.NWFiletypetoFilename - nw_filetype_2_filename.py<br/>

netwitness.NWFilename (Entity)<br/>

netwitness.NWUserAgent (Entity)<br/>


Installation
=============

Special Thanks!!
=================

Rich Popson (@Rastafari0728)<br/>
	- Drinking Partner<br/>
	- Idea Contributor to the project<br/>
	- QA Tester to the project<br/>



