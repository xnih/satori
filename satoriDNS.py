import untangle
import satoriCommon
from pathlib import Path
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer567 import dns
from datetime import datetime
from pypacker import pypacker

# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/dhcp.xml -O dhcp.xml
#
# looking for new fingerprints
# python3 satori.py -r dhcp.pcap -m dhcp > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#


# due to the sheer number of DNS entries this will display we'll default to only displaying if there is a known fingerprint
# people may want to change this to collect all DNS lookups
displayKnownFingerprintsOnly = True
#displayKnownFingerprintsOnly = False

def version():
  dateReleased='satoriDNS.py - 2023-07-02'
  print(dateReleased)

def dnsProcess(pkt, layer, ts, dnsExactList, dnsPartialList):
  if layer == 'eth':
    src_mac = pkt[ethernet.Ethernet].src_s
  else:
    #fake filler mac for all the others that don't have it, may have to add some elif above
    src_mac = '00:00:00:00:00:00'

  ip4 = pkt.upper_layer

  fingerprintDNS = None
  dnsAnswer = ''
  dnsFingerprint = ''

  timeStamp = datetime.utcfromtimestamp(ts).isoformat()

  dns1 = pkt[dns.DNS]
  for x in range(0,dns1.questions_amount):
    if dns1.answers_amount == 0 and dns1.authrr_amount == 0:
      if dns1.flags == 256 or dns1.flags == 33152:
        dnsAnswer =  pypacker.dns_name_decode(dns1.queries[x].name)[:-1]

  if (dnsAnswer != ''):
    dnsFingerprint = fingerprintLookup(dnsExactList, dnsPartialList, dnsAnswer)
    fingerprintDNS = ip4.src_s + ';' + src_mac + ';DNS;' + dnsAnswer + ';' + dnsFingerprint

  if displayKnownFingerprintsOnly == False:
    return [timeStamp, fingerprintDNS]
  elif dnsFingerprint != '':
    return [timeStamp, fingerprintDNS]


def BuildDNSFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  dnsExactList = {}
  dnsPartialList = {}

  satoriPath = str(Path(__file__).resolve().parent)
  obj = untangle.parse(satoriPath + '/fingerprints/dns.xml')
  fingerprintsCount = len(obj.DNS.fingerprints)
  for x in range(0,fingerprintsCount):
    os = obj.DNS.fingerprints.fingerprint[x]['name']
    testsCount = len(obj.DNS.fingerprints.fingerprint[x].dns_tests)
    test = {}
    for y in range(0,testsCount):
      test = obj.DNS.fingerprints.fingerprint[x].dns_tests.test[y]
      if test is None:  #if testsCount = 1, then untangle doesn't allow us to iterate through it
        test = obj.DNS.fingerprints.fingerprint[x].dns_tests.test
      matchtype = test['matchtype']
      dns = test['dns']
      weight = test['weight']
      if matchtype == 'exact':
        if dns in dnsExactList:
          oldValue = dnsExactList.get(dns)
          dnsExactList[dns] = oldValue + '|' + os + ':' + weight
        else:
          dnsExactList[dns] = os + ':' + weight
      else:
        if dns in dnsPartialList:
          oldValue = dnsPartialList.get(dns)
          dnsPartialList[dns] = oldValue + '|' + os + ':' + weight
        else:
          dnsPartialList[dns] = os + ':' + weight

  return [dnsExactList, dnsPartialList]


def fingerprintLookup(exactList, partialList, value):
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



