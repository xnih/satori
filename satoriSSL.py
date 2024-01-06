import untangle
import json
import struct
import satoriCommon
from os import remove
from os.path import exists
from pathlib import Path
from pypacker.layer12 import ethernet
from datetime import datetime
from pypacker import pypacker, triggerlist
import hashlib
import requests
from hashlib import sha256

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
    ("ciphersuite", None, triggerlist.TriggerList),  #var length
    ("compr_len", "B", 0),
    ("compression", "B", 0),
    ("ext_len", "H", 0x0000),
    ("extensions", None, triggerlist.TriggerList),
  )

  pypackerVersion = satoriCommon.checkPyPackerVersion()

  if float(pypackerVersion) >= 5.3:
    len_i = pypacker.get_property_bytes_num("len")
  else:
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
    pypackerVersion = satoriCommon.checkPyPackerVersion()

    if float(pypackerVersion) <= 5.1:
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
    else:
      sid_len = buf[38]
      offset = 38 + 1
      sid = buf[offset:offset + sid_len]
      self.sid(sid, self)
      offset = offset + sid_len
      cipsuite_len = struct.unpack('!h',buf[offset:offset+2])[0]
      offset = offset + 2
      ciphersuite = buf[offset:offset + cipsuite_len]
      self.ciphersuite(ciphersuite, self)
      offset = offset + cipsuite_len + 2
      ext_len = struct.unpack('!h',buf[offset:offset+2])[0]
      offset = offset + 2
      self.extensions(buf[offset:], self.__parse_extension)
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

  if float(pypackerVersion) >= 5.3:
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
    pypackerVersion = satoriCommon.checkPyPackerVersion()

    if float(pypackerVersion) <= 5.1:
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
    else:
      sid_len = buf[38]
      offset = 38 + 1
      sid = buf[offset:offset + sid_len]
      self.sid(sid, self)
      offset = offset + sid_len
      # the next few lines are just to bypass some stuff that isn't there in my testing so far, but left, just in case for cleanup later
      #    cipsuite_len = struct.unpack('!h',buf[offset:offset+2])[0]
      cipsuite_len = 2  # test for now
      #   offset = offset + 2
      ciphersuite = buf[offset:offset + cipsuite_len]
      self.ciphersuite(ciphersuite, self)
      offset = offset + cipsuite_len + 1
      ext_len = struct.unpack('!h', buf[offset:offset + 2])[0]
      offset = offset + 2
      self.extensions(buf[offset:], self.__parse_extension)
      offset = offset + ext_len
    return len(buf)


def version():
  dateReleased='satoriSSL.py - 2023-12-27'
  print(dateReleased)


def sslProcess(pkt, layer, ts, sslJA3XMLExactList, sslJA3SXMLExactList, sslJA3JSONExactList, sslJA4XMLExactList):  #instead of pushing the fingerprint files in each time would it make sense to make them globals?  Does it matter?
  if layer == 'eth':
    src_mac = pkt[ethernet.Ethernet].src_s
  else:
    #fake filler mac for all the others that don't have it, may have to add some elif above
    src_mac = '00:00:00:00:00:00'

  ip4 = pkt.upper_layer
  ssl1 = pkt.upper_layer.upper_layer.upper_layer

  timeStamp = datetime.utcfromtimestamp(ts).isoformat()
  fingerprint = None

  sslFingerprint = ''
  results = {}
  fingerprints = []

  if (len(ssl1.records) > 0):
    results = decodeSSLRecords(ssl1.records)

  for fpType in results:
    #lookup fingerprint needed
    hash = results[fpType]
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
        fingerprint = ip4.src_s + ';' + src_mac + ';SSL;' + fpType + ';' + hash + ';' + sslFingerprint
        fingerprints.append(fingerprint)

      elif fpType == 'ja3s':
        sslFingerprint = sslFingerprintLookup(sslJA3SXMLExactList, hash)

      elif fpType == 'ja4':
        sslFingerprint = sslFingerprintLookup(sslJA4XMLExactList, hash)

        fingerprint = ip4.src_s + ';' + src_mac + ';SSL;' + fpType + ';' + hash + ';' + sslFingerprint
        fingerprints.append(fingerprint)

  return [timeStamp, fingerprints]

def quicProcess(pkt, layer, ts, sslJA4XMLExactList):
  if layer == 'eth':
    src_mac = pkt[ethernet.Ethernet].src_s
  else:
    #fake filler mac for all the others that don't have it, may have to add some elif above
    src_mac = '00:00:00:00:00:00'

  ip4 = pkt.upper_layer
  udp1 = pkt.upper_layer.upper_layer
  print(udp1)

  timeStamp = datetime.utcfromtimestamp(ts).isoformat()
  fingerprint = None

  sslFingerprint = ''
  results = {}
  fingerprints = []

  #decode quic here
#  if (len(ssl1.records) > 0):
#    results = decodeSSLRecords(ssl1.records)
# https://www.bitahoy.com/blog/post/dissecting-quic-in-python
# First byte contains packet number length
#first_byte = raw_quic_packet[0] ^ (mask[0] & 0x0f)
#pnl = (first_byte & 0x03) + 1
# static constant
#salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

#https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection
#This process in pseudocode is:
#initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
#initial_secret = HKDF-Extract(initial_salt,client_dst_connection_id)
#client_initial_secret = HKDF-Expand-Label(initial_secret,"client in", "",Hash.length)
#server_initial_secret = HKDF-Expand-Label(initial_secret,"server in", "",Hash.length)


  for fpType in results:
    #lookup fingerprint needed
    hash = results[fpType]
    if hash != '':

      if fpType == 'ja4':
        sslFingerprint = sslFingerprintLookup(sslJA4XMLExactList, hash)

        fingerprint = ip4.src_s + ';' + src_mac + ';SSL;' + fpType + ';' + hash + ';' + sslFingerprint
        fingerprints.append(fingerprint)

  return [timeStamp, fingerprints]


def decodeSSLRecords(recs):
  ja3 = ''
  ja3s = ''
  ja4 = ''
  ja4_a = ''
  ja4_b = ''
  ja4_c = ''
  alpn = '00'
  fpType = ''
  results = {}
  version = ''
  ciphersuite = ''
  extensions = ''
  elipticleCurve = ''
  elipticleCurveFormats = ''
  supportedVersions = ''
  signatures = ''
  sni = 'i'
  delcreds = ''

  GREASE_TABLE = {'0xa0a', '0x1a1a', '0x2a2a', '0x3a3a',
                  '0x4a4a', '0x5a5a', '0x6a6a', '0x7a7a',
                  '0x8a8a', '0x9a9a', '0xaaaa', '0xbaba',
                  '0xcaca', '0xdada', '0xeaea', '0xfafa'}

  #for now ja4 will ONLY be TCP no UDP quic packets
  for rec in recs:
    if rec.type == 22: #check to see if it was a handshake
      for handshake in rec:
        if handshake.type == 1:  #check to verify client hello
          ja4_a = ja4_a + 't'
          len = handshake.len
          clientHello = clientHandshakeHello(rec.body_bytes)
          #get version doesn't really work for tls 1.3 anymore
          version = clientHello.tlsversion

          #build ciphersuite
          len = int(clientHello.cipsuite_len)
          offset = 0
          cipherCount = 0
          cipherList = []
          while offset <= len-1:
            value = struct.unpack('!H',clientHello.ciphersuite[0][offset:offset+2])[0]
            offset = offset + 2
            if hex(value) not in GREASE_TABLE:
              ciphersuite = ciphersuite + '-' + str(value)
              cipherList.append(hex(value)[2:].zfill(4))
              cipherCount = cipherCount + 1
          if ciphersuite != '':
            ciphersuite = ciphersuite[1:]
          cipherList.sort()
          cipher = ''
          for i in cipherList:
            cipher = cipher + i + ','
          cipher = cipher[:-1]
          strCipherCount = str(cipherCount).zfill(2)
          ja4_b = sha256(cipher.encode('utf-8')).hexdigest()[:12]

          #build extension
          len = int(clientHello.ext_len)
          extensionCount = 0
          extensionList = []
          sortedExtensionList = []

          for ext in clientHello.extensions:
            if hex(ext.type) not in GREASE_TABLE:
              extensionCount = extensionCount + 1
              extensions = extensions + '-' + str(ext.type)

              ignoreList = [0, 16]
              if ext.type not in ignoreList:
                extensionList.append(hex(ext.type)[2:].zfill(4))

              if ext.type == 0:  #server name
                sni = 'd'

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

              if ext.type == 13:  #signature
                offset = 0
                len = struct.unpack('!H', ext.body_bytes[offset:offset+2])[0]
                offset = offset + 2
                while offset <= len:
                  value = struct.unpack('!H',ext.body_bytes[offset:offset+2])[0]
                  signatures = signatures + ',' + hex(value)[2:].zfill(4)
                  offset = offset + 2
                if signatures != '':
                  signatures = signatures[1:]

              if ext.type == 16:  #ALPN
                offset = 0
                len = struct.unpack('!H', ext.body_bytes[offset:offset+2])[0]
                offset = offset + 2
                len = struct.unpack('!B', ext.body_bytes[offset:offset+1])[0]
                offset = offset + 1
                value = ''
                for i in range(len):
                  value = value + chr(struct.unpack('b', ext.body_bytes[offset:offset+1])[0])
                  offset = offset + 1
                alpn = value[0] + value[-1]

              # this probably isn't needed now that we've determined FoxIO's python code that was adding delegated creds was a bug in their code.  But it is parsed now in case I ever use it future.
              if ext.type == 34:  #delegated creds
                offset = 0
                len = struct.unpack('!H', ext.body_bytes[offset:offset+2])[0]
                offset = offset + 2
                while offset <= len:
                  value = struct.unpack('!H',ext.body_bytes[offset:offset+2])[0]
                  delcreds = delcreds + ',' + hex(value)[2:].zfill(4)
                  offset = offset + 2
                if delcreds != '':
                  delcreds = delcreds[1:]

              if ext.type == 43:  #supported versions
                tls = 0
                offset = 0
                len = struct.unpack('!B', ext.body_bytes[offset:offset+1])[0]
                offset = offset + 1
                while offset <= len:
                  value = str(struct.unpack('!H',ext.body_bytes[offset:offset+2])[0])
                  offset = offset + 2
                  if hex(int(value)) not in GREASE_TABLE:
                    if value == '256':
                      tls = s1
                    elif value == '512':
                      tls = s2
                    elif value == '768':
                      tls = s3
                    elif value == '769':
                      tls = 10
                    elif value == '770':
                      tls = 11
                    elif value == '771':
                      tls = 12
                    elif value == '772':
                      tls = 13
                    supportedVersions = supportedVersions + '-' + str(tls)
                if supportedVersions != '':
                  supportedVersions = supportedVersions[1:]
                #first value is preferred so using that for fingerprint
                tls = supportedVersions.split('-')[0]

          if extensions != '':
            extensions = extensions[1:]

            strExtensionCount = str(extensionCount).zfill(2)

            sortedExtensionList = extensionList.copy()
            sortedExtensionList.sort()
            extent = ''
            for i in sortedExtensionList:
              extent = extent + i + ','
            extent = extent[:-1]

            temp = extent
            if signatures != '':
              temp = temp + '_' + signatures
            else:
              temp = extent
            ja4_c = sha256(temp.encode('utf-8')).hexdigest()[:12]

          fpType = 'ja3'
          ja3 = str(version) + ',' + str(ciphersuite) + ',' + str(extensions) + ',' + str(elipticleCurve) + ',' + str(elipticleCurveFormats)
          ja3 = hashlib.md5(ja3.encode('utf-8')).hexdigest()
          results[fpType]=ja3

          fpType = 'ja4'
          ja4_a = ja4_a + str(tls) + sni + strCipherCount + strExtensionCount + alpn
          ja4 = ja4_a + '_' + ja4_b + '_' + ja4_c
          results[fpType]=ja4

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
          results[fpType] = ja3s

  return results


def ja3erUpdate():
  satoriPath = str(Path(__file__).resolve().parent)
  url = 'https://ja3er.com/getAllUasJson'
  backupurl = 'https://drive.google.com/u/0/uc?id=1M41DtHGoyghZQYsqXBJgbProGguexZoT&export=download&confirm=t&uuid=03473495-6383-40a6-86f9-3765961d134f'
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
      remove(trisulnsmFile)


def BuildSSLFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  sslJA3XMLExactList = {}
  sslJA3SXMLExactList = {}
  sslJA3JSONExactList = {}
  sslJA4XMLExactList = {}

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
        elif testtype == 'ja4':
          if sslsig in sslJA4XMLExactList:
            oldValue = sslJA4XMLExactList.get(sslsig)
            sslJA4XMLExactList[sslsig] = oldValue + '|' + os + ':' + weight
          else:
            sslJA4XMLExactList[sslsig] = os + ':' + weight
        elif testtype == 'ja3s': 
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

  return [sslJA3XMLExactList, sslJA3SXMLExactList, sslJA3JSONExactList, sslJA4XMLExactList]


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






