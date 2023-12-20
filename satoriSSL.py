import untangle
import json
import struct
import satoriCommon
from os import remove
from os.path import exists
from pathlib import Path
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from datetime import datetime
from pypacker import pypacker, triggerlist
import hashlib
import requests

class Extension(pypacker.Packet):
	"""
	Handshake protocol extension
	"""
	__hdr__ = (
		("type", "H", 0),
		("len", "H", 0)
	)

class clientHandshakeHello(pypacker.Packet):
  __hdr__ = (
    ("type", "B", 0),
    ("len", "3s", b"\x00" * 3),
    ("tlsversion", "H", 0x0301),
    ("random", "32s", b"\x00" * 32),
    ("sid_len", "B", 32),
    ("sid", None, triggerlist.TriggerList),  #var length
    ("cipsuite_len", "H", 0x0032),
    ("ciphersuite", None, triggerlist.TriggerList), #var length
    ("compr_len", "B", 0),
    ("compression", "B", 0),
    ("ext_len", "H", 0x0000),
    ("extensions", None, triggerlist.TriggerList),
  )

  pypackerVersion = satoriCommon.checkPyPackerVersion()

  if float(pypackerVersion) >= 5.4:
    len_i = pypacker.get_property_bytes_num("len")
  else: #4.9 or below use .off
    len_i = pypacker.get_property_bytes_num("len", ">I")

  @staticmethod
  def __parse_extension(buf):
    extensions = []
    offset = 0
    buflen = len(buf)

    while offset < buflen:
      ext_content_len = struct.unpack('!h', buf[offset + 2: offset + 4])[0]
      ext_len = 4 + ext_content_len
      extensions.append(Extension(buf[offset: offset + ext_len]))
      offset += ext_len

    return extensions

  def _dissect(self, buf):
    sid_len = buf[38]
    offset = 38 + 1
    sid = buf[offset:offset + sid_len]
    self.sid.append(sid)
    offset = offset + sid_len
    cipsuite_len = struct.unpack('!h',buf[offset:offset+2])[0]
    offset = offset + 2
    ciphersuite = buf[offset:offset + cipsuite_len]
    self.ciphersuite.append(ciphersuite)
    offset = offset + cipsuite_len + 2
    ext_len = struct.unpack('!h',buf[offset:offset+2])[0]
    offset = offset + 2
    self._init_triggerlist("extensions", buf[offset:], self.__parse_extension)
    offset = offset + ext_len

    return len(buf)


class serverHandshakeHello(pypacker.Packet):
  __hdr__ = (
    ("type", "B", 0),
    ("len", "3s", b"\x00" * 3),
    ("tlsversion", "H", 0x0301),
    ("random", "32s", b"\x00" * 32),
    ("sid_len", "B", 32),
    ("sid", None, triggerlist.TriggerList),  #var length
#    ("cipsuite_len", "H", 0x0032),
    ("ciphersuite", None, triggerlist.TriggerList), #var length
#    ("compr_len", "B", 0),
    ("compression", "B", 0),
    ("ext_len", "H", 0x0000),
    ("extensions", None, triggerlist.TriggerList),
  )

  pypackerVersion = satoriCommon.checkPyPackerVersion()

  #this seems to work for now, but may not be a perfect fix for the changes from 4.9 to 5.0
  if float(pypackerVersion) >= 5.4:
    len_i = pypacker.get_property_bytes_num("len")
  else: #4.9 or below use .off
    len_i = pypacker.get_property_bytes_num("len", ">I")

  @staticmethod
  def __parse_extension(buf):
    extensions = []
    offset = 0
    buflen = len(buf)

    while offset < buflen:
      ext_content_len = struct.unpack('!h', buf[offset + 2: offset + 4])[0]
      ext_len = 4 + ext_content_len
      extensions.append(Extension(buf[offset: offset + ext_len]))
      offset += ext_len

    return extensions

  def _dissect(self, buf):
    sid_len = buf[38]
    offset = 38 + 1
    sid = buf[offset:offset + sid_len]
    self.sid.append(sid)
    offset = offset + sid_len
    #the next few lines are just to bypass some stuff that isn't there in my testing so far, but left, just in case for cleanup later
#    cipsuite_len = struct.unpack('!h',buf[offset:offset+2])[0]
    cipsuite_len = 2  #test for now
#   offset = offset + 2
    ciphersuite = buf[offset:offset + cipsuite_len]
    self.ciphersuite.append(ciphersuite)
    offset = offset + cipsuite_len + 1
    ext_len = struct.unpack('!h',buf[offset:offset+2])[0]
    offset = offset + 2
    self._init_triggerlist("extensions", buf[offset:], self.__parse_extension)
    offset = offset + ext_len

    return len(buf)


def version():
  dateReleased='satoriSSL.py - 2023-03-03'
  print(dateReleased)


def sslProcess(pkt, layer, ts, sslJA3XMLExactList, sslJA3SXMLExactList, sslJA3JSONExactList):  #instead of pushing the fingerprint files in each time would it make sense to make them globals?  Does it matter?
  if layer == 'eth':
    src_mac = pkt[ethernet.Ethernet].src_s
  else:
    #fake filler mac for all the others that don't have it, may have to add some elif above
    src_mac = '00:00:00:00:00:00'

  ip4 = pkt.upper_layer
  ssl1 = pkt.upper_layer.upper_layer.upper_layer

  timeStamp = datetime.utcfromtimestamp(ts).isoformat()
  fingerprint = None

  if (len(ssl1.records) > 0):
    [fpType, hash] = decodeSSLRecords(ssl1.records)

  #lookup fingerprint needed
  if hash != '':

    if fpType == 'ja3':
      sslXMLFingerprint = sslFingerprintLookup(sslJA3XMLExactList, hash)
      sslJSONFingerprint = sslFingerprintLookup(sslJA3JSONExactList, hash)
      fingerprint = sslXMLFingerprint + '|' + sslJSONFingerprint

      if fingerprint.startswith('|'):
        fingerprint = fingerprint[1:]
      if fingerprint.endswith('|'):
        fingerprint = fingerprint[:-1]

      sslFingerprint = satoriCommon.sortFingerprint(fingerprint)
    elif fpType == 'ja3s':
      sslFingerprint = sslFingerprintLookup(sslJA3SXMLExactList, hash)

    fingerprint = ip4.src_s + ';' + src_mac + ';SSL;' + fpType + ';' + hash + ';' + sslFingerprint
  return [timeStamp, fingerprint]


def decodeSSLRecords(recs):
  ja3 = ''
  ja3s = ''
  fpType = ''
  res = ''
  version = ''
  ciphersuite = ''
  extensions = ''
  elipticleCurve = ''
  elipticleCurveFormats = ''

  GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                  0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                  0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                  0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}

  for rec in recs:
    if rec.type == 22: #check to see if it was a handshake
      for handshake in rec:
        if handshake.type == 1:  #check to verify client hello
          len = handshake.len
          clientHello = clientHandshakeHello(rec.body_bytes)

          #get version
          version = clientHello.tlsversion

          #build ciphersuite ja3 piece
          len = int(clientHello.cipsuite_len)
          offset = 0
          while offset <= len-1:
            value = struct.unpack('!H',clientHello.ciphersuite[0][offset:offset+2])[0]
            ciphersuite = ciphersuite + '-' + str(value)
            offset = offset + 2
          if ciphersuite != '':
            ciphersuite = ciphersuite[1:]

          #build extension ja3 piece
          len = int(clientHello.ext_len)
          for ext in clientHello.extensions:
            if ext.type not in GREASE_TABLE:
              extensions = extensions + '-' + str(ext.type)
            if ext.type == 10:  #elipticle curve
              offset = 0
              len = struct.unpack('!H', ext.body_bytes[offset:offset+2])[0]
              offset = offset + 2
              while offset <= len:
                value = struct.unpack('!H',ext.body_bytes[offset:offset+2])[0]
                elipticleCurve = elipticleCurve + '-' + str(value)
                offset = offset + 2
              if elipticleCurve != '':
                elipticleCurve = elipticleCurve[1:]

            if ext.type == 11:  #elipticle curve formats
              offset = 0
              len = struct.unpack('!B', ext.body_bytes[offset:offset+1])[0]
              offset = offset + 1
              while offset <= len:
                value = struct.unpack('!B',ext.body_bytes[offset:offset+1])[0]
                elipticleCurveFormats = elipticleCurveFormats + '-' + str(value)
                offset = offset + 1
              if elipticleCurveFormats != '':
                elipticleCurveFormats = elipticleCurveFormats[1:]

          if extensions != '':
            extensions = extensions[1:]

          fpType = 'ja3'
          ja3 = str(version) + ',' + str(ciphersuite) + ',' + str(extensions) + ',' + str(elipticleCurve) + ',' + str(elipticleCurveFormats)
          ja3 = hashlib.md5(ja3.encode('utf-8')).hexdigest()
          res = ja3

        elif handshake.type == 2:  #check to verify server hello
          len = handshake.len
          serverHello = serverHandshakeHello(rec.body_bytes)

          #get version
          version = serverHello.tlsversion

          #build ciphersuite ja3s piece
#          len = int(serverHello.cipsuite_len)   #doesn't exist in my test packet(s)
          len = 2
          offset = 0
          while offset <= len-1:
            value = struct.unpack('!H',serverHello.ciphersuite[0][offset:offset+2])[0]
            ciphersuite = ciphersuite + '-' + str(value)
            offset = offset + 2
          if ciphersuite != '':
            ciphersuite = ciphersuite[1:]

          #build extension ja3 piece
          len = int(serverHello.ext_len)
          for ext in serverHello.extensions:
            extensions = extensions + '-' + str(ext.type)

          if extensions != '':
            extensions = extensions[1:]

          fpType = 'ja3s'
          ja3s = str(version) + ',' + str(ciphersuite) + ',' + str(extensions)
          ja3s = hashlib.md5(ja3s.encode('utf-8')).hexdigest()
          res = ja3s

  return [fpType, res]


def ja3erUpdate():
  satoriPath = str(Path(__file__).resolve().parent)
  url = 'https://ja3er.com/getAllUasJson'
  backupurl = 'https://web.archive.org/web/20220123045913/https://ja3er.com/getAllUasJson'
  ja3erFile = satoriPath + '/fingerprints/ja3er.json'

  with open(ja3erFile, 'wb') as f:
    try:
      print('attempting to download %s, this will take awhile as it is a 210MB file...' % url)
      resp = requests.get(url, verify=False, timeout=(10, 60))  #not ideal to ignore https, but don't want to deal with certs
      f.write(resp.content)
      print('check file %s' % ja3erFile)
    except Exception as e:
      try:
        print('failed to download %s, now attempting to download from %s, this will take awhile as it is a 210MB file...' % (url, backupurl))
        resp = requests.get(backupurl, verify=False, timeout=(10, 60))  #not ideal to ignore https, but don't want to deal with certs
        f.write(resp.content)
        print('check file %s' % ja3erFile)
      except Exception as e:
        print(e)
        remove(ja3erFile)


def trisulnsmUpdate():
  satoriPath = str(Path(__file__).resolve().parent)
  url = 'https://raw.githubusercontent.com/trisulnsm/trisul-scripts/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json'
  trisulnsmFile = satoriPath + '/fingerprints/trisulnsm.json'

  with open(trisulnsmFile, 'wb') as f:
    try:
      print('attempting to download %s...' % url)
      resp = requests.get(url, verify=False, timeout=(10, 60))  #not ideal to ignore https, but don't want to deal with certs
      f.write(resp.content)
      print('check file %s' % trisulnsmFile)
    except Exception as e:
      print(e)
      remove(trisulsmFile)


def BuildSSLFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  sslJA3XMLExactList = {}
  sslJA3SXMLExactList = {}
  sslJA3JSONExactList = {}

  satoriPath = str(Path(__file__).resolve().parent)

  #xml read
  obj = untangle.parse(satoriPath + '/fingerprints/ssl.xml')
  fingerprintsCount = len(obj.SSL.fingerprints)
  for x in range(0,fingerprintsCount):
    os = obj.SSL.fingerprints.fingerprint[x]['name']
    testsCount = len(obj.SSL.fingerprints.fingerprint[x].ssl_tests)
    test = {}
    for y in range(0,testsCount):
      test = obj.SSL.fingerprints.fingerprint[x].ssl_tests.test[y]
      if test is None:  #if testsCount = 1, then untangle doesn't allow us to iterate through it
        test = obj.SSL.fingerprints.fingerprint[x].ssl_tests.test
      matchtype = test['matchtype']
      testtype = test['testtype']
      sslsig = test['sslsig']
      weight = test['weight']
      if matchtype == 'exact':
        if testtype == 'ja3':
          if sslsig in sslJA3XMLExactList:
            oldValue = sslJA3XMLExactList.get(sslsig)
            sslJA3XMLExactList[sslsig] = oldValue + '|' + os + ':' + weight
          else:
            sslJA3XMLExactList[sslsig] = os + ':' + weight
        else: #ja3s sigs (should we test or just continue to assume?)
          if sslsig in sslJA3SXMLExactList:
            oldValue = sslJA3SXMLExactList.get(sslsig)
            sslJA3SXMLExactList[sslsig] = oldValue + '|' + os + ':' + weight
          else:
            sslJA3SXMLExactList[sslsig] = os + ':' + weight

  #ja3er json load
  json_file_path = satoriPath + '/fingerprints/ja3er.json'
  weight = '5'  #added a default value of 5 for all fingerprints

  if exists(json_file_path):
    with open(json_file_path, 'r') as j:
      contents = json.loads(j.read())
    j.close()

    for fp in contents:
      sslJA3JSONExactList[fp['md5']] = fp['User-Agent'] + ':' + weight

  #trisulnsm load
  file_path = satoriPath + '/fingerprints/trisulnsm.json'
  weight = '5'  #added a default value of 5 for all fingerprints


  if exists(file_path):
    j = open(file_path, 'r')
    contents = j.readlines()
    j.close()

    # stripe all the line feeds
    contents = list(map(lambda x:x.strip(),contents))

    content = '['
    for i in contents:
      if i != "":
        if i[0] == '{':
          content += i + ','
    content = content[:-1]
    content = content + ']'

    #convert string json object
    jsonObj = json.loads(content)

    for fp in jsonObj:
      sslJA3JSONExactList[fp['ja3_hash']] = fp['desc'] + ':' + weight

  return [sslJA3XMLExactList, sslJA3SXMLExactList, sslJA3JSONExactList]


def sslFingerprintLookup(exactList, value):
  exactValue = ''

  if value in exactList:
    exactValue = exactList.get(value)

  fingerprint = exactValue
  if fingerprint.startswith('|'):
    fingerprint = fingerprint[1:]
  if fingerprint.endswith('|'):
    fingerprint = fingerprint[:-1]

  fingerprint = satoriCommon.sortFingerprint(fingerprint)
  return fingerprint






