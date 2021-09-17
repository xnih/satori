#!/bin/bash
d="0 days ago"
STAMP0=`date --date="$d" +"%Y%m%d"`

`ps aux | grep '[p]ython3 /scripts/satori/satori.py -i em2' > /tmp/em2.output`
count=`cat /tmp/em2.output | wc -l`
if [ $count -eq 0 ]
  then
    `mutt -s "Satori em2 restarted" -- "someone@wherever" < /tmp/em2.output`
fi

`kill $(ps aux | grep '[p]ython3 /scripts/satori/satori.py -i em2' | awk '{print $2}') 2>/dev/null`
`(python3 /scripts/satori/satori.py -i em2 -f "(tcp port 80 or tcp port 8080) and (src net 10.0.0.0/8)" -m http,tcp -l 1 >> /var/log/satori/em2-$STAMP0.log &) > /dev/null 2>&1`
