#!/bin/bash
d="0 days ago"
STAMP0=`date --date="$d" +"%Y%m%d"`

`ps aux | grep '[p]ython3 /scripts/satori/satori.py -i em4' > /tmp/em4.output`
count=`cat /tmp/em4.output | wc -l`
if [ $count -eq 0 ]
  then
    `mutt -s "Satori em4 restarted" -- "someone@somewhere" < /tmp/em4.output`
fi

`kill $(ps aux | grep '[p]ython3 /scripts/satori/satori.py -i em4' | awk '{print $2}') 2>/dev/null`
`(python3 /scripts/satori/satori.py -i em4 -f "(udp port 67 or udp port 68 or tcp port 445 or udp port 445)" -m smb,dhcp -l 1 >> /var/log/satori/em4-$STAMP0.log &) > /dev/null 2>&1`
