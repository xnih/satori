import untangle
import satoriCommon
from pathlib import Path
from datetime import datetime
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip

# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/tcp.xml -O tcp.xml
#
# looking for new fingerprints
# python3 satori.py > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#


def version():
  dateReleased='satoriHTTP.py - 2025-12-22'
  print(dateReleased)


def httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList):
  if layer == 'eth':
    src_mac = pkt[ethernet.Ethernet].src_s
  else:
    #fake filler mac for all the others that don't have it, may have to add some elif above
    src_mac = '00:00:00:00:00:00'

  ip4 = pkt.upper_layer
  tcp1 = pkt.upper_layer.upper_layer
  http1 = pkt.upper_layer.upper_layer.upper_layer

  timeStamp = datetime.utcfromtimestamp(ts).isoformat()
  hdrServer = ''
  bodyServer = ''

  try:
    if (http1.hdr != None) and (http1.hdr):
      hdr = dict(http1.hdr)
      hdrServer = hdr[b'Server'].decode("utf-8", "strict")
    if (http1.body_bytes):
      body = http1.body_bytes.decode("utf-8", "strict")
      i = body.find("Server: ")
      if i > 1:
        v = body[i:]
        i = v.find("\n")
        v = v[:i]
        i = v.find(":")
        bodyServer = v[i+1:].strip()
  except Exception as e:
    pass

  fingerprintHdrServer = None
  fingerprintBodyServer = None

  if (hdrServer != ''):
    httpServerFingerprint = fingerprintLookup(serverExactList, serverPartialList, hdrServer.lower())
    #not ideal but converting any ; to | for parsing reasons!
#    changedUserAgent = hdrUserAgent.replace(';', '|')
    fingerprintHdrServer = ip4.src_s + ';' + src_mac + ';HTTPSERVER;' + hdrServer + ';' + httpServerFingerprint
  if (bodyServer != ''):
    httpServerFingerprint = fingerprintLookup(serverExactList, serverPartialList, bodyServer.lower())
    #not ideal but converting any ; to | for parsing reasons!
#    changedUserAgent = bodyUserAgent.replace(';', '|')
    fingerprintBodyServer = ip4.src_s + ';' + src_mac + ';HTTPSERVER;' + bodyServer + ';' + httpServerFingerprint
  return [timeStamp, fingerprintHdrServer, fingerprintBodyServer]


def httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList):
  if layer == 'eth':
    src_mac = pkt[ethernet.Ethernet].src_s
  else:
    #fake filler mac for all the others that don't have it, may have to add some elif above
    src_mac = '00:00:00:00:00:00'

  ip4 = pkt.upper_layer
  tcp1 = pkt.upper_layer.upper_layer
  http1 = pkt.upper_layer.upper_layer.upper_layer

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
  except Exception as e:
    pass

  fingerprintHdrUserAgent = None
  fingerprintBodyUserAgent = None

  if (hdrUserAgent != ''):
    httpUserAgentFingerprint = fingerprintLookup(useragentExactList, useragentPartialList, hdrUserAgent.lower())
    #not ideal but converting any ; to | for parsing reasons!
    changedUserAgent = hdrUserAgent.replace(';', '|').replace("\n", "").replace("\r", "").strip()
    fingerprintHdrUserAgent = ip4.src_s + ';' + src_mac + ';USERAGENT;' + changedUserAgent + ';' + httpUserAgentFingerprint
  if (bodyUserAgent != ''):
    httpUserAgentFingerprint = fingerprintLookup(useragentExactList, useragentPartialList, bodyUserAgent.lower())
    #not ideal but converting any ; to | for parsing reasons!
    changedUserAgent = bodyUserAgent.replace(';', '|').replace("\n", "").replace("\r", "").strip()
    fingerprintBodyUserAgent = ip4.src_s + ';' + src_mac + ';USERAGENT;' + changedUserAgent + ';' + httpUserAgentFingerprint

  return [timeStamp, fingerprintHdrUserAgent, fingerprintBodyUserAgent]


def BuildHTTPServerFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  serverExactList = {}
  serverPartialList = {}

  satoriPath = str(Path(__file__).resolve().parent)

  obj = untangle.parse(satoriPath + '/fingerprints/web.xml')
  fingerprintsCount = len(obj.WEBSERVER.fingerprints)
  for x in range(0,fingerprintsCount):
    os = obj.WEBSERVER.fingerprints.fingerprint[x]['name']
    testsCount = len(obj.WEBSERVER.fingerprints.fingerprint[x].webserver_tests)
    test = {}
    for y in range(0,testsCount):
      test = obj.WEBSERVER.fingerprints.fingerprint[x].webserver_tests.test[y]
      if test is None:  #if testsCount = 1, then untangle doesn't allow us to iterate through it
        test = obj.WEBSERVER.fingerprints.fingerprint[x].webserver_tests.test
      matchtype = test['matchtype']
      webserver = test['webserver']
      weight = test['weight']
      if matchtype == 'exact':
        if webserver in serverExactList:
          oldValue = serverExactList.get(webserver)
          serverExactList[webserver] = oldValue + '|' + os + ':' + weight
        else:
          serverExactList[webserver] = os + ':' + weight
      else:
        if webserver in serverPartialList:
          oldValue = serverPartialList.get(webserver)
          serverPartialList[webserver] = oldValue + '|' + os + ':' + weight
        else:
          serverPartialList[webserver] = os + ':' + weight

  return [serverExactList, serverPartialList]



def BuildHTTPUserAgentFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  useragentExactList = {}
  useragentPartialList = {}

  satoriPath = str(Path(__file__).resolve().parent)

  obj = untangle.parse(satoriPath + '/fingerprints/webuseragent.xml')
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
      webuseragent = test['webuseragent'].lower()
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


def fingerprintLookup(exactList, partialList, value):
  #same as DHCP one, may be able to look at combining in the future?
  exactValue = ''
  partialValue = ''

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

  fingerprint = satoriCommon.sortFingerprint(fingerprint)
  return fingerprint






