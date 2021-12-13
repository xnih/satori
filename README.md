# satori
Python rewrite of passive OS fingerprinting tool.

It currently supports fingerprinting by the following means:
- DHCP
- TCP
- HTTP (User Agent and Server)
- SMB (TCP and UDP)
- SSL (JA3/JA3S) 

This program was started back in 2004 and had a decent life as a windows program, doing passive OS fingerprinting for 10 years with regular updates, but it fell by the wayside.  It has been a goal to get it back out here, written in something that I could share the code with others.  

I am NOT a programmer, I hack code together, so this is what it is.  Time permitting I'll continue to bring new modules into this that were in the windows version and more importantly update the fingerprint files.

## ssl - if you want more fingerprints
You'll need to download the ja3er.com json file if you want a decent DB of fingerprints, otherwise the xml version that is part of satori right now is primarily from sslbl.abuse.ch/ja3-fingerprints

To download the j3er.com ones do a 'satori.py --ja3update'.  Though please be aware it is going to ignore the cert when it goes to download this, if you are not comfortable with that grab the file manually and drop it in the fingerprint directory.

## requirements
### os related
- libpcap-dev

### os related Armbian
- python3-dev 

### python related
- python3
- pypacker*
- pcapy*  (depending on distro may need these installed prior:libpcap-dev, python3-dev; along with setuptools if using pip3 to install)
- untangle*

#### optional
- netifaces* (while not specifically needed saves some error messages at least on rasbianos)

*(if you use pip to install it, remember to use pip3)

## updates:

periodically get the latest fingerprint files and any updates:
- git pull

## use:
- python3 satori.py -r [some pcap] -m [one of the modules]
- python3 satori.py -i [some interface] -m [one of the modules]

modules feature is optional

I have added the ability to listen to live packets, but be aware, you are running as root typically to do this, use at own risk as mentioned before, I am by no means a programmer!

## graylog
I'm only a novice working with graylog, but feeding satori logs into it is much faster for processing through them after the fact than grep!

You can do things like " NOT os_guess:* " to find devices that satori was unable to provide a guess at the OS.

The content pack currently contains about 5 rules to properly parse the data.  It may not be ideal on how they are configured, I've spent a very limited amount of timing with graylog!  It has worked well enough for what I've done in testing.  nxlog would probably be a good way to inject them into graylog, but to date I've just used netcat and pushed them into a raw tcp listener!

## version
This currently really is version 0.1 of this.  Just to reiterate I am not a programmer, expecially in python, I just hack stuff together, so you have been warned.  But with that said, seems stable at this point and I've been running it in production like systems since I put this out here!
