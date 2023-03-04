import xml.etree.ElementTree as ET
import pkg_resources
from pathlib import Path

def version():
  dateReleased='satoriCommon.py - 2021-12-13'
  print(dateReleased)


def getImportVersions():
  print("\n3rd party imports needed to make Satori work: (pypacker, untangle, and (pcapy or pcapyplus)")
  print("pypacker: %s" % (pkg_resources.get_distribution('pypacker').version))
  try:
    print("pcapy: %s" % (pkg_resources.get_distribution('pcapy').version))
  except:
    pass

  try:
    print("pcapyplus: %s" % (pkg_resources.get_distribution('pcapyplus').version))
  except:
    pass

  print("untagle: %s" % (pkg_resources.get_distribution('untangle').version))


def findDupes(path):
  tree = ET.parse(path)
  root = tree.getroot()

  for fingerprints in root:
    for fingerprint in fingerprints:
      for testtype in fingerprint:
        setOfElems = set()
        for test in testtype:
          val = str(test.attrib)
          if val in setOfElems:
            print("found duplicate in: %s; %s:%s" % (path, fingerprint.attrib['name'], test.attrib))
          else:
            setOfElems.add(val)

def checkPyPackerVersion():
  pypackerVersion = pkg_resources.get_distribution('pypacker').version
  return pypackerVersion


def Dupes():
  print('Checking for Dupes')
  satoriPath = str(Path(__file__).resolve().parent)

  findDupes(satoriPath + '/fingerprints/browser.xml')
  findDupes(satoriPath + '/fingerprints/dhcpv6.xml')
  findDupes(satoriPath + '/fingerprints/dhcp.xml')
  findDupes(satoriPath + '/fingerprints/mac.xml')
  findDupes(satoriPath + '/fingerprints/sip.xml')
  findDupes(satoriPath + '/fingerprints/smb.xml')
  findDupes(satoriPath + '/fingerprints/tcp.xml')
  findDupes(satoriPath + '/fingerprints/ssl.xml')
  findDupes(satoriPath + '/fingerprints/webuseragent.xml')
  findDupes(satoriPath + '/fingerprints/web.xml')


def sort_key(val):
  return int(val[1])


def sortFingerprint(fp):
  if '|' in fp:
    fingerprints = fp.split('|')

    list = []
    listOfFingerprints = []
    for fingerprint in fingerprints:
      parts = fingerprint.split(':')
      list = [parts[0], parts[1]]
      listOfFingerprints.append(list)
    listOfFingerprints.sort(key=sort_key,reverse=True)

    fp = ''
    for fingerprint in listOfFingerprints:
      info = ''
      for val in fingerprint:
        info = info + ":" + val
      fp = fp + '|' + info[1:]

    if fp[0] == '|':
      fp = fp[1:]

  return fp
