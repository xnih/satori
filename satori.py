from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
from pypacker.layer567 import dhcp
from pypacker.layer567 import http
from pypacker import pypacker
from datetime import datetime
import getopt
import time
import sys
import os
import signal
import satoriTCP
import satoriDHCP
import satoriHTTP

def usage():
    print("""
    -r, --read        pcap to read in; example: -r tcp.pcap
    -i, --interface   interface to listen to; example: -i eth0 (not implemented yet)
    -m, --modules     modules to load; example: -m tcp,dhcp
    -l, --log         log file to write output to; example -l output.txt (not implemented yet)
    -v, --verbose     verbose logging, mostly just telling you where/what we're doing, not recommended if want to parse output typically
    """)

def dhcpProcess(eth, ts, DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, DeclineTTLExactList):

  ip4 = eth.upper_layer
  udp1 = eth.upper_layer.upper_layer
  timeStamp = datetime.utcfromtimestamp(ts/1000000000).isoformat()

  #print ("src port: %s; dst port: %s" % (udp1.sport, udp1.dport))  #check to see if udp port 67 or 68 or should that be done before sending here?  or does the dhcp.DHCP handle?
  dhcp1 = eth[dhcp.DHCP]
  MessageType=satoriDHCP.getDHCPMessageType(dhcp1.op)
  clientAddr = dhcp1.ciaddr_s
  yourAddr = dhcp1.yiaddr_s
  nextServerAddr = dhcp1.siaddr_s
  relayServerAddr = dhcp1.giaddr_s
  clientMAC = pypacker.mac_bytes_to_str(dhcp1.chaddr[0:6])  #dump the padding is pypacker copies it all together

  [options, messageType, option55, vendorCode] = satoriDHCP.getDHCPOptions(dhcp1.opts)
  osGuessOptions = ''
  osGuessOption55 = ''
  osGuessVendorCode = ''
  if messageType == 'Discover':
    if options != '':
      osGuessOptions = satoriDHCP.DHCPFingerprintLookup(DiscoverOptionsExactList, DiscoverOptionsPartialList, options)
      print("%s;%s;%s;DHCP;%s;Options;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, options, osGuessOptions))
    if option55 != '':
      osGuessOption55 = satoriDHCP.DHCPFingerprintLookup(DiscoverOption55ExactList, DiscoverOption55PartialList, option55)
      print("%s;%s;%s;DHCP;%s;Option55;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, option55, osGuessOption55))
    if vendorCode != '':
      osGuessVendorCode = satoriDHCP.DHCPFingerprintLookup(DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, vendorCode)
      print("%s;%s;%s;DHCP;%s;VendorCode;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, vendorCode, osGuessVendorCode))
  elif messageType == 'Offer':
    if options != '':
      osGuessOptions = satoriDHCP.DHCPFingerprintLookup(OfferOptionsExactList, OfferOptionsPartialList, options)
      print("%s;%s;%s;DHCP;%s;Options;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, options, osGuessOptions))
    if option55 != '':
      osGuessOption55 = satoriDHCP.DHCPFingerprintLookup(OfferOption55ExactList, OfferOption55PartialList, option55)
      print("%s;%s;%s;DHCP;%s;Option55;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, option55, osGuessOption55))
    if vendorCode != '':
      osGuessVendorCode = satoriDHCP.DHCPFingerprintLookup(OfferVendorCodeExactList, OfferVendorCodePartialList, vendorCode)
      print("%s;%s;%s;DHCP;%s;VendorCode;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, vendorCode, osGuessVendorCode))
  elif messageType == 'Request':
    if options != '':
      osGuessOptions = satoriDHCP.DHCPFingerprintLookup(RequestOptionsExactList, RequestOptionsPartialList, options)
      print("%s;%s;%s;DHCP;%s;Options;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, options, osGuessOptions))
    if option55 != '':
      osGuessOption55 = satoriDHCP.DHCPFingerprintLookup(RequestOption55ExactList, RequestOption55PartialList, option55)
      print("%s;%s;%s;DHCP;%s;Option55;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, option55, osGuessOption55))
    if vendorCode != '':
      osGuessVendorCode = satoriDHCP.DHCPFingerprintLookup(RequestVendorCodeExactList, RequestVendorCodePartialList, vendorCode)
      print("%s;%s;%s;DHCP;%s;VendorCode;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, vendorCode, osGuessVendorCode))
  elif messageType == 'Decline':
    if options != '':
      osGuessOptions = satoriDHCP.DHCPFingerprintLookup(DeclineOptionsExactList, DeclineOptionsPartialList, options)
      print("%s;%s;%s;DHCP;%s;Options;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, options, osGuessOptions))
    if option55 != '':
      osGuessOption55 = satoriDHCP.DHCPFingerprintLookup(DeclineOption55ExactList, DeclineOption55PartialList, option55)
      print("%s;%s;%s;DHCP;%s;Option55;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, option55, osGuessOption55))
    if vendorCode != '':
      osGuessVendorCode = satoriDHCP.DHCPFingerprintLookup(DeclineVendorCodeExactList, DeclineVendorCodePartialList, vendorCode)
      print("%s;%s;%s;DHCP;%s;VendorCode;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, vendorCode, osGuessVendorCode))
  elif messageType == 'ACK':
    if options != '':
      osGuessOptions = satoriDHCP.DHCPFingerprintLookup(ACKOptionsExactList, ACKOptionsPartialList, options)
      print("%s;%s;%s;DHCP;%s;Options;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, options, osGuessOptions))
    if option55 != '':
      osGuessOption55 = satoriDHCP.DHCPFingerprintLookup(ACKOption55ExactList, ACKOption55PartialList, option55)
      print("%s;%s;%s;DHCP;%s;Option55;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, option55, osGuessOption55))
    if vendorCode != '':
      osGuessVendorCode = satoriDHCP.DHCPFingerprintLookup(ACKVendorCodeExactList, ACKVendorCodePartialList, vendorCode)
      print("%s;%s;%s;DHCP;%s;VendorCode;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, vendorCode, osGuessVendorCode))
  elif messageType == 'NAK':
    if options != '':
      osGuessOptions = satoriDHCP.DHCPFingerprintLookup(NAKOptionsExactList, NAKOptionsPartialList, options)
      print("%s;%s;%s;DHCP;%s;Options;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, options, osGuessOptions))
    if option55 != '':
      osGuessOption55 = satoriDHCP.DHCPFingerprintLookup(NAKOption55ExactList, NAKOption55PartialList, option55)
      print("%s;%s;%s;DHCP;%s;Option55;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, option55, osGuessOption55))
    if vendorCode != '':
      osGuessVendorCode = satoriDHCP.DHCPFingerprintLookup(NAKVendorCodeExactList, NAKVendorCodePartialList, vendorCode)
      print("%s;%s;%s;DHCP;%s;VendorCode;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, vendorCode, osGuessVendorCode))
  elif messageType == 'Release':
    if options != '':
      osGuessOptions = satoriDHCP.DHCPFingerprintLookup(ReleaseOptionsExactList, ReleaseOptionsPartialList, options)
      print("%s;%s;%s;DHCP;%s;Options;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, options, osGuessOptions))
    if option55 != '':
      osGuessOption55 = satoriDHCP.DHCPFingerprintLookup(ReleaseOption55ExactList, ReleaseOption55PartialList, option55)
      print("%s;%s;%s;DHCP;%s;Option55;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, option55, osGuessOption55))
    if vendorCode != '':
      osGuessVendorCode = satoriDHCP.DHCPFingerprintLookup(ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, vendorCode)
      print("%s;%s;%s;DHCP;%s;VendorCode;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, vendorCode, osGuessVendorCode))
  elif messageType == 'Inform':
    if options != '':
      osGuessOptions = satoriDHCP.DHCPFingerprintLookup(InformOptionsExactList, InformOptionsPartialList, options)
      print("%s;%s;%s;DHCP;%s;Options;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, options, osGuessOptions))
    if option55 != '':
      osGuessOption55 = satoriDHCP.DHCPFingerprintLookup(InformOption55ExactList, InformOption55PartialList, option55)
      print("%s;%s;%s;DHCP;%s;Option55;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, option55, osGuessOption55))
    if vendorCode != '':
      osGuessVendorCode = satoriDHCP.DHCPFingerprintLookup(InformVendorCodeExactList, InformVendorCodePartialList, vendorCode)
      print("%s;%s;%s;DHCP;%s;VendorCode;%s;%s" % (timeStamp,clientAddr, clientMAC, messageType, vendorCode, osGuessVendorCode))



def tcpProcess(eth, ts, sExactList, saExactList, sPartialList, saPartialList):  #instead of pushing the fingerprint files in each time would it make sense to make them globals?  Does it matter?
  ip4 = eth.upper_layer
  tcp1 = eth.upper_layer.upper_layer

  # lets verify we have tcp options and it is a SYN or SYN/ACK packet
  if (len(tcp1.opts) > 0) and ((tcp1.flags == 0x02) or (tcp1.flags == 0x12)):
    p0fSignature = ''
    tcpSignature = ''
    ethercapSignature = ''

    #print("%s:%s -> %s:%s" % (eth[ip.IP].src_s, eth[tcp.TCP].sport, eth[ip.IP].dst_s, eth[tcp.TCP].dport))

    [ipVersion, ipHdrLen] = satoriTCP.computeIP(ip4.v_hl)
    [ethTTL, ttl] = satoriTCP.computeNearTTL(ip4.ttl)
    [df, mf, offset] = satoriTCP.computeIPOffset(ip4.off)

    winSize = tcp1.win
    tcpFlags = satoriTCP.computeTCPFlags(tcp1.flags)
    tcpHdrLen = satoriTCP.computeTCPHdrLen(tcp1.off_x2)
    [tcpOpts, tcpTimeStampEchoReply, mss] = satoriTCP.decodeTCPOptions(tcp1.opts)

    odd = satoriTCP.detectOddities(ip4, ipHdrLen, ipVersion, tcpHdrLen, tcpFlags, tcp1, tcpOpts, tcpTimeStampEchoReply)


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
      tcpFingerprint = satoriTCP.TCPFingerprintLookup(sExactList, sPartialList, tcpSignature)
    elif tcpFlags == 'SA':
      tcpFingerprint = satoriTCP.TCPFingerprintLookup(saExactList, saPartialList, tcpSignature)
    #ignore anything that is not S or SA, but should probably clean that up prior to this point!
    timeStamp = datetime.utcfromtimestamp(ts/1000000000).isoformat()


    print("%s;%s;%s;TCP;%s;%s;%s" % (timeStamp,eth[ethernet.Ethernet].src_s, eth[ip.IP].src_s, tcpFlags, tcpSignature, tcpFingerprint))
    #print("%s;%s;p0fv2;%s;%s;%s" % (timeStamp,eth[ethernet.Ethernet].src_s, eth[ip.IP].src_s, tcpFlags, p0fSignature, p0fv2Fingerprint))
    #print("%s;%s;Ettercap;%s;%s;%s" % (timeStamp,eth[ethernet.Ethernet].src_s, eth[ip.IP].src_s, tcpFlags, ettercapSignature, ettercapFingerprint))


def httpUserAgentProcess(eth, ts, useragentExactList, useragentPartialList):
  ip4 = eth.upper_layer
  tcp1 = eth.upper_layer.upper_layer
  http1 = eth.upper_layer.upper_layer.upper_layer

  timeStamp = datetime.utcfromtimestamp(ts/1000000000).isoformat()
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
    httpUserAgentFingerprint = satoriHTTP.httpUserAgentFingerprintLookup(useragentExactList, useragentPartialList, hdrUserAgent)
    #not ideal but converting any ; to | for parsing reasons!
    changedUserAgent = hdrUserAgent.replace(';', '|')
    print("%s;%s;%s;USERAGENT;%s;%s" % (timeStamp,eth[ethernet.Ethernet].src_s, eth[ip.IP].src_s, changedUserAgent, httpUserAgentFingerprint))
  if (bodyUserAgent != ''):
    httpUserAgentFingerprint = satoriHTTP.httpUserAgentFingerprintLookup(useragentExactList, useragentPartialList, bodyUserAgent)
    #not ideal but converting any ; to | for parsing reasons!
    changedUserAgent = bodyUserAgent.replace(';', '|')
    print("%s;%s;%s;USERAGENT;%s;%s" % (timeStamp,eth[ethernet.Ethernet].src_s, eth[ip.IP].src_s, changedUserAgent, httpUserAgentFingerprint))


def main():
  #override some warning settings in pypacker.  May need to change this to .CRITICAL in the future, but for now we're trying .ERROR
  #without this when parsing http for example we get "WARNINGS" when packets aren't quite right in the header.
  logger = pypacker.logging.getLogger("pypacker")
  pypacker.logger.setLevel(pypacker.logging.ERROR)

  counter = 0
  startTime = time.time()
  tcpCheck = False
  dhcpCheck = False
  httpCheck = False

  #read in fingerprints
  [sExactList, saExactList, sPartialList, saPartialList] = satoriTCP.BuildTCPFingerprintFiles()
  [DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, DeclineTTLExactList] = satoriDHCP.BuildDHCPFingerprintFiles()
  [useragentExactList, useragentPartialList] = satoriHTTP.BuildHTTPUserAgentFingerprintFiles()

  if len(modules) == 0:
    #no preference so we'll run all modules we have
    tcpCheck = True
    dhcpCheck = True
    httpCheck = True
  else:
    #requested a specific one, so lets only enable what was asked for
    mod = modules.split(',')
    for i in range(len(mod)):
      if (mod[i].lower() == 'tcp'):
        tcpCheck = True
      elif (mod[i].lower() == 'dhcp'):
        dhcpCheck = True
      elif (mod[i].lower() == 'http'):
        httpCheck = True

  if readpcap != '':
    preader = ppcap.Reader(filename=readpcap)
  elif interface != '':
    preader = ''  #need to get it to read an interface instead, but quick/dirty to address a check
  else:  #we should never get here with "proceed" check, but just in case
    preader = ''
    print("Not sure how we got here")

  for ts, buf in preader:
    try:
      counter = counter + 1

      eth = ethernet.Ethernet(buf)

      if (eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None) and tcpCheck:
        tcpProcess(eth, ts, sExactList, saExactList, sPartialList, saPartialList)
      if (eth[ethernet.Ethernet, ip.IP, udp.UDP, dhcp.DHCP] is not None) and dhcpCheck:
        dhcpProcess(eth, ts, DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, DeclineTTLExactList)
      if (eth[ethernet.Ethernet, ip.IP, tcp.TCP, http.HTTP] is not None) and httpCheck:
        httpUserAgentProcess(eth, ts, useragentExactList, useragentPartialList)
        # add http ServerProcess at later date
    except (KeyboardInterrupt, SystemExit):
      raise
    except:
      pass

  endTime = time.time()
  totalTime = endTime - startTime

  if verbose:
    print ('Total Time: %s, Total Packets: %s, Packets/s: %s' % (totalTime, counter, counter / totalTime ))

try:
  opts, args = getopt.getopt(sys.argv[1:], "r:m:i:l:v", [ 'read=', 'modules=', 'interface=', 'log=', 'verbose'])

  readpcap = interface = modules = log = ''
  proceed = False
  verbose = False

  for opt, val in opts:
    if opt in ('-r', '--read'):
      if not os.path.isfile(val):
        print ('\nFile "%s" does not appear to exist, please verify pcap file name.' % val)
        sys.exit()
      else:
        proceed = True
        readpcap = val
    if opt in ('-m', '--modules'):
      modules = val
    if opt in ('-i', '--interface'):  #not implemented yet
      interface = val
      proceed = True
      # run a check to verify legit interface when we get to that.
    if opt in ('-l', '--log'):  #not implemented yet
      log = val
      # do a check to see if file already exists, if so open in append mode, else create
    if opt in ('-v', '--verbose'):
      verbose = True

  if (__name__ == '__main__') and proceed:
    main()
  else:
    print('Need to provide a pcap to read in or an interface to watch')
    usage()

except getopt.error:
     usage()



