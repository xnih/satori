import untangle
import struct
from datetime import datetime
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip

# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/tcp.xml -O tcp.xml
#
# looking for new fingerprints
# python3 satori.py > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
#

def httpUserAgentProcess(eth, ts, useragentExactList, useragentPartialList):
  ip4 = eth.upper_layer
  tcp1 = eth.upper_layer.upper_layer
  http1 = eth.upper_layer.upper_layer.upper_layer

  timeStamp = datetime.utcfromtimestamp(ts).isoformat()
  hdrUserAgent = ''
  bodyUserAgent = ''

  try:
    if (http1.hdr != None) and (http1.hdr):
      hdr = dict(http1.hdr)
      hdrUserAgent = hdr[b'User-Agent'].decode("utf-8", "strict")
    if (http1.body_bytes):
      body = http1.body_bytes.decode("utf-8", "strict")
      i = body.find("User-Agent: ") 
      if i > 1:
        v = body[i:]
        i = v.find("\n")
        v = v[:i]
        i = v.find(":")
        bodyUserAgent = v[i+1:].strip()
  except:
    pass

  if (hdrUserAgent != ''):
    httpUserAgentFingerprint = httpUserAgentFingerprintLookup(useragentExactList, useragentPartialList, hdrUserAgent)
    #not ideal but converting any ; to | for parsing reasons!
    changedUserAgent = hdrUserAgent.replace(';', '|')
    print("%s;%s;%s;USERAGENT;%s;%s" % (timeStamp, eth[ip.IP].src_s, eth[ethernet.Ethernet].src_s, changedUserAgent, httpUserAgentFingerprint))
  if (bodyUserAgent != ''):
    httpUserAgentFingerprint = httpUserAgentFingerprintLookup(useragentExactList, useragentPartialList, bodyUserAgent)
    #not ideal but converting any ; to | for parsing reasons!
    changedUserAgent = bodyUserAgent.replace(';', '|')
    print("%s;%s;%s;USERAGENT;%s;%s" % (timeStamp,eth[ethernet.Ethernet].src_s, eth[ip.IP].src_s, changedUserAgent, httpUserAgentFingerprint))



def BuildHTTPUserAgentFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  useragentExactList = {}
  useragentPartialList = {}

  obj = untangle.parse('fingerprints/webuseragent.xml')
  fingerprintsCount = len(obj.WEBUSERAGENT.fingerprints)
  for x in range(0,fingerprintsCount):
    os = obj.WEBUSERAGENT.fingerprints.fingerprint[x]['name']
    testsCount = len(obj.WEBUSERAGENT.fingerprints.fingerprint[x].webuseragent_tests)
    test = {}
    for y in range(0,testsCount):
      test = obj.WEBUSERAGENT.fingerprints.fingerprint[x].webuseragent_tests.test[y]
      if test is None:  #if testsCount = 1, then untangle doesn't allow us to iterate through it
        test = obj.WEBUSERAGENT.fingerprints.fingerprint[x].webuseragent_tests.test
      matchtype = test['matchtype']
      webuseragent = test['webuseragent']
      weight = test['weight']
      if matchtype == 'exact':
        if webuseragent in useragentExactList:
          oldValue = useragentExactList.get(webuseragent)
          useragentExactList[webuseragent] = oldValue + '|' + os + ':' + weight
        else:
          useragentExactList[webuseragent] = os + ':' + weight
      else:
        if webuseragent in useragentPartialList:
          oldValue = useragentPartialList.get(webuseragent)
          useragentPartialList[webuseragent] = oldValue + '|' + os + ':' + weight
        else:
          useragentPartialList[webuseragent] = os + ':' + weight

  return [useragentExactList, useragentPartialList]




def httpUserAgentFingerprintLookup(exactList, partialList, value):
  #same as DHCP one, may be able to look at combining in the future?
  exactValue = ''
  partialValue = ''
  print (value)

  if value in exactList:
    exactValue = exactList.get(value)

  for key, val in partialList.items():
    if value.find(key) > -1:
      partialValue = partialValue + '|' + val

  if partialValue.startswith('|'):
    partialValue = partialValue[1:]
  if partialValue.endswith('|'):
    partialValue = partialValue[:-1]

  fingerprint = exactValue + '|' + partialValue
  if fingerprint.startswith('|'):
    fingerprint = fingerprint[1:]
  if fingerprint.endswith('|'):
    fingerprint = fingerprint[:-1]

  return fingerprint



