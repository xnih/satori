# satori
Python rewrite of passive OS fingerprinting tool.

It currently supports fingerprinting by the following means:
- DHCP
- TCP
- HTTP (User Agent and Server)
- SMB (TCP and UDP)

This program was started back in 2004 and had a decent life as a windows program, doing passive OS fingerprinting for 10 years with regular updates, but it fell by the wayside.  It has been a goal to get it back out here, written in something that I could share the code with others.  

I am NOT a programmer, I hack code together, so this is what it is.  Time permitting I'll continue to bring new modules into this that were in the windows version and more importantly update the fingerprint files.

## requirements
### os related
- libpcap-dev

### python related
- python3
- pypacker*
- pcapy*  (make sure you have libpcap-dev installed prior!)
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

This currently really is version 0.1 of this.  Just to reiterate I am not a programmer, expecially in python, I just hack stuff together, so you have been warned.  But with that said, seems stable at this point!
