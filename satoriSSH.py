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
  dateReleased='satoriSSH.py - 2021-01-04'
  print(dateReleased)


def sshProcess(pkt, layer, ts, sshExactList, sshPartialList):
  if layer == 'eth':
    src_mac = pkt[ethernet.Ethernet].src_s
  else:
    #fake filler mac for all the others that don't have it, may have to add some elif above
    src_mac = '00:00:00:00:00:00'

  ip4 = pkt.upper_layer
  tcp1 = pkt.upper_layer.upper_layer

  timeStamp = datetime.utcfromtimestamp(ts).isoformat()
  ssh = ''

  try:
    temp = tcp1.body_bytes.decode("utf-8").strip()
    #may need to expand this test in the future, but don't want to only do port 22 for example, so simple test for now.
    if temp[0:3] == 'SSH':
      ssh = temp
  except:
    pass

  fingerprintSSH = None

  if (ssh != ''):
    sshFingerprint = fingerprintLookup(sshExactList, sshPartialList, ssh)
    fingerprintSSH = ip4.src_s + ';' + src_mac + ';SSH;' + ssh + ';' + sshFingerprint

  return [timeStamp, fingerprintSSH]


def BuildSSHFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  serverExactList = {}
  serverPartialList = {}

  satoriPath = str(Path(__file__).resolve().parent)

  obj = untangle.parse(satoriPath + '/fingerprints/ssh.xml')
  fingerprintsCount = len(obj.SSH.fingerprints)
  for x in range(0,fingerprintsCount):
    os = obj.SSH.fingerprints.fingerprint[x]['name']
    testsCount = len(obj.SSH.fingerprints.fingerprint[x].ssh_tests)
    test = {}
    for y in range(0,testsCount):
      test = obj.SSH.fingerprints.fingerprint[x].ssh_tests.test[y]
      if test is None:  #if testsCount = 1, then untangle doesn't allow us to iterate through it
        test = obj.SSH.fingerprints.fingerprint[x].ssh_tests.test
      matchtype = test['matchtype']
      ssh = test['ssh']
      weight = test['weight']
      if matchtype == 'exact':
        if ssh in serverExactList:
          oldValue = serverExactList.get(ssh)
          serverExactList[ssh] = oldValue + '|' + os + ':' + weight
        else:
          serverExactList[ssh] = os + ':' + weight
      else:
        if ssh in serverPartialList:
          oldValue = serverPartialList.get(ssh)
          serverPartialList[ssh] = oldValue + '|' + os + ':' + weight
        else:
          serverPartialList[ssh] = os + ':' + weight

  return [serverExactList, serverPartialList]



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






