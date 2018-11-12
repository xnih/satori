# satori
Python rewrite of passive OS fingerprinting tool

This program was started backin 2004 and had a decent life as a windows program, doing passive OS fingerprinting for 10 years with regular updates, but it feel by the wayside.  It has been a goal to get it back out here, written in something that I could share the code with others.  

I am NOT a programmer, I hack code together, so this is what it is.  Time permitting I'll continue to bring new modules into this that were in the windows version and more importantly update the fingerprint files that will continue to be hosted on my ancient, very ugly, on purpose, website!

requirements:
python3
pypacker  (if you use pip to install it, remember to use pip3)

initial setup:

chmod +x fingerprintupdate.sh

periodically get the latest fingerprint files:
./fingerprintingupdate.sh

use:
python3 -r [some pcap] -m [one of the modules]

modules feature is optional

At this time, only reads in precaptured pcaps, no live/on the fly stuff, but since you have to run tcpdump as root normally, means bad coding on my part is less likely to hose you!

This currently really is version 0.1 of this.  Just to reiterate I am not a programmer, expecially in python, I just hack stuff together, so you have been warned.  But with that said, seems stable at this point!
