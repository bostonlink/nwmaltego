NWMaltego

Author: David Bressler (@bostonlink)

[start Disclaimer]

I am not the best coder and I just make things work, so, any problems found with my code submit a solution.  If you just want to complain about my code, please go elsewhere ;)

[end Disclaimer]

NWMaltego is a multi-platform python project that integrates Netwitness and Maltego together.  It allows for an analyst to graphically map Netwitness data within Maltego.  It includes several new entities and multiple transforms to pull data from Netwitness.

NWmodule.py

nwmodule.py is a python module I wrote that interfaces with the Netwitness REST API.  All Maltego transforms are dependent on this module and functions within it.  It must ne within the directory that contains the Maltego transforms.

Netwitness.conf

The netwitness.conf file holds data about the netwitness environment, user credentials, and the location for an output directory where the file extractor transform will save an exracted file from a Netwitness session.

All Other Python Files

All other files not mention above are the actual Maltego transforms that Maltego will run as local transforms on an analysts system.


Installation


Special Thanks!!

Rich Popson (@Rastafari0728)
	- Drinking Partner
	- Idea Contributor to the project
	- QA Tester to the project



