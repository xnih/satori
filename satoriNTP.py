import untangle
import satoriCommon
from pathlib import Path
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer567 import ntp
from datetime import datetime
from pypacker import pypacker

# https://datatracker.ietf.org/doc/html/rfc5905
# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/dhcp.xml -O dhcp.xml
#
# looking for new fingerprints
# python3 satori.py -r dhcp.pcap -m dhcp > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#

def version():
  dateReleased='satoriNTP.py - 2023-07-03'
  print(dateReleased)

def ntpProcess(pkt, layer, ts, ntpExactList, ntpPartialList):
  if layer == 'eth':
    src_mac = pkt[ethernet.Ethernet].src_s
  else:
    #fake filler mac for all the others that don't have it, may have to add some elif above
    src_mac = '00:00:00:00:00:00'

  ip4 = pkt.upper_layer
  udp1 = pkt.upper_layer.upper_layer
  ntp1 = pkt[ntp.NTP]

  fingerprintNTP = None

  timeStamp = datetime.utcfromtimestamp(ts).isoformat()

  sport = udp1.sport

  leap = ntp1.li
  version = ntp1.v
  mode = ntp1.mode

  stratum = ntp1.stratum
  poll = ntp1.interval
  precision = ntp1.precision
  delay = ntp1.delay

  dispersion = ntp1.dispersion

  id = pypacker.ip4_bytes_to_str(ntp1.id)

  [referenceTime, referenceVal] = ntpTimeConvert(ntp1.update_time, ts)
  [originateTime, originateVal] = ntpTimeConvert(ntp1.originate_time, ts)
  [receiveTime, receiveVal] = ntpTimeConvert(ntp1.receive_time, ts)
  [transmitTime, transmitVal] = ntpTimeConvert(ntp1.transmit_time, ts)

  #sport needs to be either 123 or 1024+
  if sport > 1024:
    sport = 1025

  if id != '0.0.0.0':
    idVal = 'set'
  else:
    idVal = 'unset'

# ones with no value that I can find:
# stratum, precision, delay

# minimal use?
# dispersion, it switches based on who it is talking to for time
  #mode
  # 1 = symmetric active
  # 2 = symmetric passive
  # 3 = client
  # 4 = server
  # 5 = broadcastServer
  # 6 = broadcastClient

  if mode == 1:
    fingerprint = 'active;' + str(sport) + ',' + str(leap) + ',' + str(version) + ',' + str(poll) + ',' + str(get16bitSecs(dispersion)) + ',' + idVal + ',' + referenceVal + ',' + transmitVal
  elif mode == 2:
    # probably will remove this one?
    fingerprint = 'passive;' + str(sport) + ',' + str(leap) + ',' + str(version) + ',' + str(poll) + ',' + str(get16bitSecs(dispersion)) + ',' + idVal + ',' + referenceVal + ',' + transmitVal
  elif mode == 3:
    fingerprint = 'client;' + str(sport) + ',' + str(leap) + ',' + str(version) + ',' + str(poll) + ',' + str(get16bitSecs(dispersion)) + ',' + idVal + ',' + referenceVal + ',' + transmitVal
#  elif mode == 4:
    #poll seemed to be from client it was replying too
#    fingerprint = 'server;' + str(sport) + ',' + str(leap) + ',' + str(version) + ',' + str(get16bitSecs(dispersion)) + ',' + idVal + ',' + referenceVal + ',' + transmitVal

  ntpFingerprint = ''

  if (fingerprint != ''):
    ntpFingerprint = fingerprintLookup(ntpExactList, ntpPartialList, fingerprint)

  fingerprintNTP = ''
  fingerprintNTP = ip4.src_s + ';' + src_mac + ';NTP;' + fingerprint + ';' + ntpFingerprint
  return [timeStamp, fingerprintNTP]


def get16bitSecs(value):
  return(value >> 16)


def get16bitFrac(value):
  return(value & 0xFFFF)


def ntpTimeConvert(ntpTime, packetTime):
  value = ''
  #why we need an offset and only part of the info  https://tickelton.gitlab.io/articles/ntp-timestamps/
  offset = 2208988800
  time = int.from_bytes(ntpTime[0:4], "big")
  if time > offset:
    time = time - offset

  if time == 0:
    value = '0'
  else:
    randomAssValue = 2000
    secDiff = packetTime - time
    if secDiff < -randomAssValue:
      value = 'random'  #past
    elif secDiff < randomAssValue:
      value = 'current'
    else:
      value = 'random'  #future
  timeStamp = datetime.utcfromtimestamp(time).strftime('%Y-%m-%dT%H:%M:%S')

  return (timeStamp, value)

def BuildNTPFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  ntpExactList = {}
  ntpPartialList = {}

  satoriPath = str(Path(__file__).resolve().parent)
  obj = untangle.parse(satoriPath + '/fingerprints/ntp.xml')
  fingerprintsCount = len(obj.NTP.fingerprints)
  for x in range(0,fingerprintsCount):
    os = obj.NTP.fingerprints.fingerprint[x]['name']
    testsCount = len(obj.NTP.fingerprints.fingerprint[x].ntp_tests)
    test = {}
    for y in range(0,testsCount):
      test = obj.NTP.fingerprints.fingerprint[x].ntp_tests.test[y]
      if test is None:  #if testsCount = 1, then untangle doesn't allow us to iterate through it
        test = obj.NTP.fingerprints.fingerprint[x].ntp_tests.test
      matchtype = test['matchtype']
      ntp = test['ntp']
      weight = test['weight']
      if matchtype == 'exact':
        if ntp in ntpExactList:
          oldValue = ntpExactList.get(ntp)
          ntpExactList[ntp] = oldValue + '|' + os + ':' + weight
        else:
          ntpExactList[ntp] = os + ':' + weight
      else:
        if ntp in ntpPartialList:
          oldValue = ntpPartialList.get(ntp)
          ntpPartialList[ntp] = oldValue + '|' + os + ':' + weight
        else:
          ntpPartialList[ntp] = os + ':' + weight

  return [ntpExactList, ntpPartialList]


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



