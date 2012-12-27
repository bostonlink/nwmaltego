NWMaltego
==========

Author: David Bressler (@bostonlink)  <br/>
Demo Video: http://a1.video3.blip.tv/0340025695473/Bostonlink-NetwitnessMaltegoIntegrationDemoNWMaltego652.m4v  <br/>
Demo Video: http://www.pentest-labs.org/blog/netwitness-maltego-integration-demo-video  <br/>

### About


NWMaltego is a multi-platform python project that integrates Netwitness and Maltego together.  It allows for an analyst to graphically map Netwitness data within Maltego.  It includes several new entities and multiple transforms to pull data from Netwitness.

### NWmodule.py

nwmodule.py is a python module I wrote that interfaces with the Netwitness REST API.  All Maltego transforms are dependent on this module and functions within it.  It must ne within the directory that contains the Maltego transforms.

### Netwitness.conf

The netwitness.conf file holds data about the netwitness environment, user credentials, and the location for an output directory where the file extractor transform will save an exracted file from a Netwitness session.

### Maltego Transforms

Listing of all current Netwitness Maltego transforms and the filename and entity they are associated wtih
```
maltego.IPv4Address (Entity)

    netwitness.NWIPDsttoThreat - nw_ip_dst_threat.py
    netwitness.NWIPSourcetoThreat - nw_ip_src_threat.py
    netwitness.NWIPSRCandDSTtoThreat - nw_ipsrc_dst_threat.py
    netwitness.NWIPtoFileType - nw_ip_2_filetype.py
    netwitness.NWIPtoFilename - nw_ip_2_filename.py
    netwitness.NWIPdestinationtoIPSource - nw_ipdst_2_ip_src.py
    netwitness.NWIPSourcetoIPDestination - nw_ipsrc_2_ip_dst.py
    netwitness.NWIPtoUserAgent - nw_ip_2_UA.py
    netwitness.NWIPtoHostnameAlias - nw_ip_2_hostname_alias.py
    netwitness.LaunchNetwitness - nw_launcher_win.py (Windows Only Transform)

maltego.Phrase (Entity)

    netwitness.NWPhrasetoThreat - nw_phrase_2_threat.py

netwitness.NWThreatNOIP (Entity)
    
    netwitness.NWThreatNoIPtoAllIPAddresses - nw_threat_2_ip_all.py
    netwitness.NWThreatNOIPtoFilename - nw_threat_2_filename.py
    netwitness.NWThreatNoIPtoFiletype - nw_threat_2_filetype.py
    netwitness.NWThreatNOIPtoFileAttachment - nw_threat_2_file_attachment.py
    netwitness.NWThreatNoIPtoIPSrc - nw_threat_2_ip_src.py
    netwitness.NWThreatNoIPtoIPDst - nw_threat_2_ip_dst.py
    netwitness.NWThreatNOIPtoUserAgent - nw_threat_2_UA.py

netwitness.NWThreat (Entity)

    netwitness.NWThreattoIPDestination - nw_threat_2_ip_dst.py
    netwitness.NWThreattoIPSource - nw_threat_2_ip_src.py
    netwitness.NWThreattoFiletype - nw_threat_2_filetype.py
    netwitness.NWThreattoFilename - nw_threat_2_filename.py
    netwitness.NWThreattoFileAttachment - nw_threat_2_file_attachment.py
    netwitness.NWThreattoUserAgent - nw_threat_2_UA.py
    netwitness.NWThreattoIPall - nw_threat_2_ip_all.py

netwitness.NWFiletype (Entity)

    netwitness.NWFiltypetoThreat - nw_filetype_2_threat.py
    netwitness.NWFiletypetoFilename - nw_filetype_2_filename.py

netwitness.NWFilename (Entity)

netwitness.NWUserAgent (Entity)
```

### Installation

The only multiplatform dependency is Python 2.7.

Addtionally, Netwitness's REST API must be enabled, it is not enabled by default on some appliances. Check the docs!

#### [Linux and OSX]

* git clone the repository  
* git clone git://github.com/bostonlink/nwmaltego.git
* Move the repo to the /opt/ directory `mv nwmaltego/ /opt/`
* Edit the netwitness.conf file with your Netwitness environment settings
* Import the `import/nwmaltego-config.mtz` file into Maltego and you should be good to go

Note: The Maltego configuration files have explicit references to the directories that hold the transforms.
It is possible to change the location of the local transforms however, you will have to edit all of the imported
transforms and edit the working directory of all the transforms.

#### [Windows]

* git clone the repository
* git clone git://github.com/bostonlink/nwmaltego.git

```Note: If you download the zip file from github it will name the file and directory nwmaltego-master. 

Rename the directory to nwmaltego.```

* Move the repo to the root of C:\ - Example: `C:\nwmaltego` should store the contents of the repo.
* Edit the netwitness.conf file with your Netwitness environment settings
* Import the `import/nwmaltego-config-windows.mtz` file into Maltego and you should be good to go

Note: The Maltego configuration files have explicit references to the directories that hold the transforms.
It is possible to change the location of the local transforms however, you will have to edit all of the imported
transforms and edit the working directory of all the transforms.

### Special Thanks!!

Rich Popson (@Rastafari0728)
* Drinking Partner
* nwmaltego Idea Contributor
* nwmaltego QA Tester

Paterva (@Paterva)

Nadeem Douba (@ndouba)

MassHackers (@MassHackers)
