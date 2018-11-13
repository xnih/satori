import untangle
import struct


# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/tcp.xml -O tcp.xml
#
# looking for new fingerprints
# python3 satori.py > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
#


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

  if value in exactList:
    exactValue = exactList.get(value)

  for key, val in partialList.items():
    if value.find(key) > -1:
      partialValue = val

  fingerprint = exactValue + '|' + partialValue
  if fingerprint.startswith('|'):
    fingerprint = fingerprint[1:]
  if fingerprint.endswith('|'):
    fingerprint = fingerprint[:-1]

  return fingerprint



