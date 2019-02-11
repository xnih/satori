import untangle
import struct
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
#from pypacker.layer4 import tcp
from datetime import datetime


# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/tcp.xml -O tcp.xml
#
# looking for new fingerprints
# python3 satori.py > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#


def tcpProcess(eth, ts, sExactList, saExactList, sPartialList, saPartialList):  #instead of pushing the fingerprint files in each time would it make sense to make them globals?  Does it matter?
  ip4 = eth.upper_layer
  tcp1 = eth.upper_layer.upper_layer

  # lets verify we have tcp options and it is a SYN or SYN/ACK packet
  if (len(tcp1.opts) > 0) and ((tcp1.flags == 0x02) or (tcp1.flags == 0x12)):
    p0fSignature = ''
    tcpSignature = ''
    ethercapSignature = ''

    #print("%s:%s -> %s:%s" % (eth[ip.IP].src_s, eth[tcp.TCP].sport, eth[ip.IP].dst_s, eth[tcp.TCP].dport))

    [ipVersion, ipHdrLen] = computeIP(ip4.v_hl)
    [ethTTL, ttl] = computeNearTTL(ip4.ttl)
    [df, mf, offset] = computeIPOffset(ip4.off)

    winSize = tcp1.win
    tcpFlags = computeTCPFlags(tcp1.flags)
    tcpHdrLen = computeTCPHdrLen(tcp1.off_x2)
    [tcpOpts, tcpTimeStampEchoReply, mss] = decodeTCPOptions(tcp1.opts)

    odd = detectOddities(ip4, ipHdrLen, ipVersion, tcpHdrLen, tcpFlags, tcp1, tcpOpts, tcpTimeStampEchoReply)


    #build p0fv2 signature
    found = False
    if (winSize != 0) and (mss != 0):
      if ((winSize % mss) == 0):
        p0fSignature = p0fSignature + 'S' + str(winSize // mss) + ':'
        found = True
      mtu = mss + 40  #probably should verify if this should be 40 or _ip_hlen + _tcp_hlen
      if ((winSize % mtu) == 0):
        p0fSignature = p0fSignature + 'T' + str(winSize // mtu) + ':'
        found = True
      if (found == False):
        p0fSignature = p0fSignature + str(winSize) + ':'
    else:
      p0fSignature = p0fSignature + str(winSize) + ':'
    p0fSignature = p0fSignature + str(ttl) + ':' + str(df) + ':' + str(ipHdrLen + tcpHdrLen) + ':' + tcpOpts + ':' + odd


    #build EtterCap Signature  (needs finished out, not complete)
    if winSize == '':
      etterWinSize = '_MSS'
    else:
      etterWinSize = hex(winSize).lstrip("0x").upper()
    etterMSS = hex(mss).lstrip("0x").rjust(4,"0").upper()
    try:
      x = tcpOpts.find('W')
      if (x > 0):
        ws = tcpOpts[x+1::]
        x = ws.find(',')
        if (x > 0):
          ws = ws[0:x]
        ws = hex(int(ws)).lstrip("0x").rjust(2,"0")
      else:
        ws = 'WS'
    except:
      ws = 'WS'  #may need to do something else, but good enough for now
    ettercapSignature = etterWinSize + ':' + etterMSS + ':' + hex(ttl).lstrip("0x") + ':' + ws + ':' # + sack, NOP anywhere, DF, Timestamp Present, Flag of packet (s or a), len

    #build Satori tcp Signature
    tcpSignature = str(winSize) + ':' + str(ttl) + ':' + str(df) + ':' + str(ipHdrLen + tcpHdrLen) + ':' + tcpOpts + ':' + odd
    if tcpFlags == 'S':
      tcpFingerprint = TCPFingerprintLookup(sExactList, sPartialList, tcpSignature)
    elif tcpFlags == 'SA':
      tcpFingerprint = TCPFingerprintLookup(saExactList, saPartialList, tcpSignature)
    #ignore anything that is not S or SA, but should probably clean that up prior to this point!
    timeStamp = datetime.utcfromtimestamp(ts).isoformat()


    print("%s;%s;%s;TCP;%s;%s;%s" % (timeStamp, eth[ip.IP].src_s, eth[ethernet.Ethernet].src_s, tcpFlags, tcpSignature, tcpFingerprint))
    #print("%s;%s;p0fv2;%s;%s;%s" % (timeStamp, eth[ip.IP].src_s, eth[ethernet.Ethernet].src_s, tcpFlags, p0fSignature, p0fv2Fingerprint))
    #print("%s;%s;Ettercap;%s;%s;%s" % (timeStamp, eth[ip.IP].src_s, eth[ethernet.Ethernet].src_s, tcpFlags, ettercapSignature, ettercapFingerprint))



def BuildTCPFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  sExactList = {}
  saExactList = {}
  sPartialList = {}
  saPartialList = {}

  obj = untangle.parse('fingerprints/tcp.xml')
  fingerprintsCount = len(obj.TCP.fingerprints)
  for x in range(0,fingerprintsCount):
    os = obj.TCP.fingerprints.fingerprint[x]['name']
    testsCount = len(obj.TCP.fingerprints.fingerprint[x].tcp_tests)
    test = {}
    for y in range(0,testsCount):
      test = obj.TCP.fingerprints.fingerprint[x].tcp_tests.test[y]
      if test is None:  #if testsCount = 1, then untangle doesn't allow us to iterate through it
        test = obj.TCP.fingerprints.fingerprint[x].tcp_tests.test
      matchtype = test['matchtype']
      tcpflag = test['tcpflag']
      tcpsig = test['tcpsig']
      weight = test['weight']
      if matchtype == 'exact':
        if tcpflag == 'S':
          if tcpsig in sExactList:
            oldValue = sExactList.get(tcpsig)
            sExactList[tcpsig] = oldValue + '|' + os + ':' + weight
          else:
            sExactList[tcpsig] = os + ':' + weight
        else: #SA packets
          if tcpsig in saExactList:
            oldValue = saExactList.get(tcpsig)
            saExactList[tcpsig] = oldValue + '|' + os + ':' + weight
          else:
            saExactList[tcpsig] = os + ':' + weight
      else:
        if tcpflag == 'S':
          if tcpsig in sPartialList:
            oldValue = sPartialList.get(tcpsig)
            sPartialList[tcpsig] = oldValue + '|' + os + ':' + weight
          else:
            sPartialList[tcpsig] = os + ':' + weight
        else: #SA packets
          if tcpsig in saPartialList:
            oldValue = saPartialList.get(tcpsig)
            saPartialList[tcpsig] = oldValue + '|' + os + ':' + weight
          else:
            saPartialList[tcpsig] = os + ':' + weight

  return [sExactList, saExactList, sPartialList, saPartialList]




def TCPFingerprintLookup(exactList, partialList, value):
  exactValue = ''
  partialValue = ''

  if value in exactList:
    exactValue = exactList.get(value)

  if '*' in value:
    #create values with * in the correct potential locations as well
    newValue4 = ''
    splitValue = value.split(':')
    splitValue4 = splitValue[4].split(',')
    for x in range(0, len(splitValue4)):
      if 'W' in splitValue4[x]:
        newValue4 = newValue4 + 'W*,'
      else:
        newValue4 = newValue4 + splitValue4[x] + ','
    newValue4 = newValue4[:-1]

    newValue1 = splitValue[0] + ':' + splitValue[1] + ':*:' + splitValue[3] + ':' + newValue4 + ':' + splitValue[5]
    newValue2 = splitValue[0] + ':' + splitValue[1] + ':' + splitValue[2] + ':' + splitValue[3] + ':' + newValue4 + ':' + splitValue[5]
    newValue3 = splitValue[0] + ':' + splitValue[1] + ':*:' + splitValue[3] + ':' + splitValue[4] + ':' + splitValue[5]

    if newValue1 in partialList:
      partialValue = partialList.get(newValue1)
    if newValue2 in partialList:
      partialValue = partialList.get(newValue2)
    if newValue3 in partialList:
      partialValue = partialList.get(newValue3)

  fingerprint = exactValue + '|' + partialValue
  if fingerprint.startswith('|'):
    fingerprint = fingerprint[1:]
  if fingerprint.endswith('|'):
    fingerprint = fingerprint[:-1]

  return fingerprint



def detectOddities(_ip, _ip_hlen, _ip_type, _tcp_hlen, _tcp_flags, _tcp, _tcp_options, _options_er):

  odd = ''
  if _tcp_options[:-1] == 'E':
    odd = odd + 'P'

  if _ip.id == 0:
    odd = odd + 'Z'

  if _ip_hlen > 20:
    odd = odd + 'I'

  if _ip_type == 4:
    len = _ip.len - _tcp_hlen - _ip_hlen

# not sure if my code even in Delphi handled ipv6, so commented out for now.
#  if _ip_type == 6:
#    len = _ipv6.dlen - _tcp_hlen - _ip_hlen

  if len > 0:
    odd = odd + 'D'

  if ('U' in _tcp_flags):
    odd = odd + 'U'

  if ((_tcp_flags == 'S' or _tcp_flags == 'SA') and _tcp.ack != 0):
    odd = odd + 'A'

  if (_tcp_flags == 'S' and _options_er != 0):
    odd = odd + 'T'

  if _tcp_flags == 'SA':
    if ('T' in _tcp_options):
      odd = odd + 'T'

  temp = _tcp_flags
  temp = temp.replace('S', '')
  temp = temp.replace('A', '')
  if (temp != ''):
    odd = odd + 'F'

  if odd == '':
    odd = '.'

  return odd



def decodeTCPOptions(opts):
  res = ''
  mss = 0
  tcpTimeStampEchoReply = ''

  for i in opts:
    if i.type == 0:
      res = res + 'E,'
    elif i.type == 1:
      res = res + 'N,'
    elif i.type == 2:
      mss = struct.unpack('!h',i.body_bytes)[0]
      res = res + 'M' + str(mss) + ','
    elif i.type == 3:
      x = struct.unpack('!b',i.body_bytes)[0]
      res = res + 'W' + str(x) + ','
    elif i.type == 4:
      res = res + 'S,'
    elif i.type == 5:
      res = res + 'K,' 
    elif i.type == 6:
      res = res + 'J,'
    elif i.type == 7:
      res = res + 'F,'  
      #print("Options Echo (need to compute?):  %s" % (i.body_bytes))
    elif i.type == 8:
      res = res + 'T,'
      tcpTimeStamp = struct.unpack('!I',i.body_bytes[0:4])[0]
      tcpTimeStampEchoReply = struct.unpack('!I',i.body_bytes[4:8])[0] 
    elif i.type == 9:
      res = res + 'P,'
    elif i.type == 10:
      res = res + 'R,'
#    elif i.type == 11:
#      res = res + ','
#    elif i.type == 12:
#      res = res + ','
#    elif i.type == 13:
#      res = res + ','
#    elif i.type == 14:
#      res = res + ','
#    elif i.type == 15:
#      res = res + ','
#    elif i.type == 16:
#      res = res + ','
#    elif i.type == 17:
#      res = res + ','
#    elif i.type == 18:
#      res = res + ','
#    elif i.type == 19:
#      res = res + ','
#    elif i.type == 20:
#      res = res + ','
#    elif i.type == 21:
#      res = res + ','
#    elif i.type == 22:
#      res = res + ','
#    elif i.type == 23:
#      res = res + ','
#    elif i.type == 24:
#      res = res + ','
#    elif i.type == 25:
#      res = res + ','
#    elif i.type == 26:
#      res = res + ','
#    elif i.type == 27:
#      res = res + ','
    else:
      res = res + 'U,'
      print('unknown TCP Options')


#    x=len(i.body_bytes)
#    if x == 0:
#      print("Type: %s" % (i.type))
#    else:
      # we should check endianness, but based on quick tests, even though I'm little it was big on MSS, so just using ! for now.
      #print(sys.byteorder)
#      if x == 1:
#        val = "!b"
#      elif x == 2:
#        val = "!h" 
#      elif x == 4:
#        val = "!l"
#      elif x == 8:   #while timestamp (type 8) is length 8, it is really 2x 4's, so have to look at this closer later
#        val = "!d"
#      print("Type: %s, Value: %s" % (i.type, struct.unpack(val,i.body_bytes)[0]))
    #print("Type: %s, Value: %s" % (i.type, i.body_bytes))
  return(res[:-1], tcpTimeStampEchoReply, mss)


def computeTCPFlags(flags):
  tcpFlags = ''
  if flags == 0x02:
    tcpFlags = 'S'
#  elif flags == 0x10:
#    tcpFlags = 'A'
  elif flags == 0x12:
    tcpFlags = 'SA'
#  else:
#    tcpFlags = flags  #do I need/want this?  If we have packets with tcp options that are not S or SA we are ignoring, so NO, we do not want this
  return(tcpFlags)


def computeIP(info):
  ipVersion = int('0x0' + hex(info)[2],16)
  ipHdrLen = int('0x0' + hex(info)[3],16) * 4  
  return [ipVersion, ipHdrLen]


def computeNearTTL(info):
  if (info>0) and (info<=16):
    ttl = 16
    ethTTL = 16
  elif (info>16) and (info<=32):
    ttl = 32 
    ethTTL = 43
  elif (info>32) and (info<=60):
    ttl = 60 #unlikely to find many of these anymore
    ethTTL = 64
  elif (info>60) and (info<=64):
    ttl = 64
    ethTTL = 64
  elif (info>64) and (info<=128):
    ttl = 128
    ethTTL = 128
  elif (info>128):
    ttl = 255
    ethTTL = 255
  else:
    ttl = info
    ethTTL = info
  return [ethTTL, ttl]


def computeIPOffset(info):  
  # need to see if I can find a way to import these from ip.py as they are already defined there.
  # Fragmentation flags (ip_off)
  IP_RF = 0x4   # reserved
  IP_DF = 0x2   # don't fragment
  IP_MF = 0x1   # more fragments (not last frag)

  res = 0
  df = 0
  mf = 0

  flags = (info & 0xE000) >> 13
  offset = (info & ~0xE000)

  if (flags & IP_RF) > 0:
    res = 1
  if (flags & IP_DF) > 0:
    df = 1
  if (flags & IP_MF) > 0:
    mf = 1

  return [df, mf, offset]


def computeTCPHdrLen(info):
  tcpHdrLen = (info >> 4) * 4
  return tcpHdrLen



