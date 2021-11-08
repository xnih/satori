from pypacker import ppcap
from pypacker import pcapng
from pypacker.layer12 import ethernet
from pypacker.layer12 import linuxcc
from pypacker.layer3 import ip
from pypacker.layer3 import icmp
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
from pypacker.layer567 import dhcp
from pypacker.layer567 import http
from pypacker import pypacker
import datetime
import pcapy
import getopt
import time
import sys
import os
import signal
import satoriTCP
import satoriDHCP
import satoriHTTP
#import satoriICMP
import satoriSMB
import satoriCommon

def versionInfo():
  dateReleased='satori.py - 2021-11-08'
  print(dateReleased)
  satoriTCP.version()
  satoriDHCP.version()
  satoriHTTP.version()
  satoriSMB.version()
  satoriCommon.version()

def usage():
    print("""
    -d, --directory   directory to read all pcaps in a dir (does NOT do sub directories); example -d /pcaps
    -r, --read        pcap to read in; example: -r tcp.pcap
    -i, --interface   interface to listen to; example: -i eth0
    -m, --modules     modules to load; example: -m tcp,dhcp
    -f, --filter      bpf filter to apply (only implemented in live capture processing); example: -f "tcp port 80 or tcp port 8080"
    -l, --limit       limit the number of same events written in a time period (in minutes); example -l 1
    -v, --verbose     verbose logging, mostly just telling you where/what we're doing, not recommended if want to parse output typically
    --version         print dates for the different modules
    --dupes           check for dupes in the fingerprint files
    """, end='\n', flush=True)


def packetType(buf):
  tcpPacket = False
  dhcpPacket = False
  httpPacket = False
  udpPacket = False

  #try to determine what type of packets we have, there is the chance that 0x800 may be in the spot we're checking, may want to add better testing in future
  eth = ethernet.Ethernet(buf)
  if hex(eth.type) == '0x800':
    layer = 'eth'
    pkt = eth

    if (eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None):
      tcpPacket = True
    if (eth[ethernet.Ethernet, ip.IP, udp.UDP, dhcp.DHCP] is not None):
      dhcpPacket = True
    if (eth[ethernet.Ethernet, ip.IP, tcp.TCP, http.HTTP] is not None):
      httpPacket = True
    if (eth[ethernet.Ethernet, ip.IP, udp.UDP] is not None):
      udpPacket = True

  lcc = linuxcc.LinuxCC(buf)
  if hex(lcc.type) == '0x800':
    layer = 'lcc'
    pkt = lcc

    if (lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP] is not None):
      tcpPacket = True
    if (lcc[linuxcc.LinuxCC, ip.IP, udp.UDP, dhcp.DHCP] is not None):
      dhcpPacket = True
    if (lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP, http.HTTP] is not None):
      httpPacket = True
    if (lcc[linuxcc.LinuxCC, ip.IP, udp.UDP] is not None):
      udpPacket = True

  return(pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket)


def printCheck(timeStamp, fingerprint):

  if fingerprint != None:
    if limit != '':
      if fingerprint in historyCheck:
        value = historyCheck[fingerprint]
        FMT = '%Y-%m-%dT%H:%M:%S'
        tdelta = datetime.datetime.strptime(timeStamp, FMT) - datetime.datetime.strptime(value, FMT)
        if tdelta > datetime.timedelta(minutes=historyTime):
          print("%s;%s" % (timeStamp, fingerprint), end='\n', flush=True)
          historyCheck[fingerprint]=timeStamp
      else:
        print("%s;%s" % (timeStamp, fingerprint), end='\n', flush=True)
        historyCheck[fingerprint]=timeStamp
    else:
      print("%s;%s" % (timeStamp, fingerprint), end='\n', flush=True)

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
  icmpCheck = False  #not enabled in lower code at this point due to tracking features I'm not willing to code at this time.
  smbCheck = False

  #read in fingerprints
  [sExactList, saExactList, sPartialList, saPartialList] = satoriTCP.BuildTCPFingerprintFiles()
  [DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, DeclineTTLExactList] = satoriDHCP.BuildDHCPFingerprintFiles()
  [useragentExactList, useragentPartialList] = satoriHTTP.BuildHTTPUserAgentFingerprintFiles()
  [serverExactList, serverPartialList] = satoriHTTP.BuildHTTPServerFingerprintFiles()
  #[icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList] = satoriICMP.BuildICMPFingerprintFiles()
  [nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList] = satoriSMB.BuildSMBTCPFingerprintFiles()
  [browserExactList, browserPartialList] = satoriSMB.BuildSMBUDPFingerprintFiles()

  #check pypacker version
  pypackerVersion = satoriCommon.checkPyPackerVersion()
  print(pypackerVersion)

  if len(modules) == 0:
    tcpCheck = True
    dhcpCheck = True
    httpCheck = True
    icmpCheck = True
    smbCheck = True
  else:
    mod = modules.split(',')
    for i in range(len(mod)):
      if (mod[i].lower() == 'tcp'):
        tcpCheck = True
      elif (mod[i].lower() == 'dhcp'):
        dhcpCheck = True
      elif (mod[i].lower() == 'http'):
        httpCheck = True
      elif (mod[i].lower() == 'icmp'):
        icmpCheck = True
      elif (mod[i].lower() == 'smb'):
        smbCheck = True

  if (directory != ''):  #probably a better way to do this and dupe most of the below code from preader section, but DHCP passing parameters into a procedure sucks.
    onlyfiles = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    for f in onlyfiles:
      try:
        preader = ppcap.Reader(filename=directory + '/' + f)

        for ts, buf in preader:
          try:
            counter = counter + 1
            ts = ts/1000000000

            (pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket) = packetType(buf)
            if tcpPacket and tcpCheck:
              [timeStamp, fingerprint] = satoriTCP.tcpProcess(pkt, layer, ts, pypackerVersion, sExactList, saExactList, sPartialList, saPartialList)
              printCheck(timeStamp, fingerprint)
            if dhcpPacket and dhcpCheck:
              [timeStamp, fingerprintOptions, fingerprintOption55, fingerprintVendorCode] = satoriDHCP.dhcpProcess(
                                     pkt, layer, ts, DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, 
                                     ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, 
                                     InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, 
                                     ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, 
                                     AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, 
                                     RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, 
                                     ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, 
                                     DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, 
                                     AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, 
                                     NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, 
                                     OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, 
                                     OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, 
                                     DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, 
                                     DeclineTTLExactList)
              printCheck(timeStamp, fingerprintOptions)
              printCheck(timeStamp, fingerprintOption55)
              printCheck(timeStamp, fingerprintVendorCode)
            if httpPacket and httpCheck:
              [timeStamp, fingerprintHdrUserAgent, fingerprintBodyUserAgent] = satoriHTTP.httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList)
              printCheck(timeStamp, fingerprintHdrUserAgent)
              printCheck(timeStamp, fingerprintBodyUserAgent)
              [timeStamp, fingerprintHdrServer, fingerprintBodyServer] = satoriHTTP.httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList)
              printCheck(timeStamp, fingerprintHdrServer)
              printCheck(timeStamp, fingerprintBodyServer)
#            if (eth[ethernet.Ethernet, ip.IP, icmp.ICMP] is not None) and icmpCheck:
#              satoriICMP.icmpProcess(eth, ts, icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList)
            if tcpPacket and smbCheck:
              [timeStamp, fingerprintOS, fingerprintLanMan] = satoriSMB.smbTCPProcess(pkt, layer, ts, nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList)
              printCheck(timeStamp, fingerprintOS)
              printCheck(timeStamp, fingerprintLanMan)
            if udpPacket and smbCheck:
              [timeStamp, fingerprint] = satoriSMB.smbUDPProcess(pkt, layer, ts, browserExactList, browserPartialList)
              printCheck(timeStamp, fingerprint)
          except (KeyboardInterrupt, SystemExit):
            raise
          except:
            pass
      except:
        pass  #file not in pcap format


  elif (readpcap != ''):
    try:
      preader = ppcap.Reader(filename=readpcap)
    except:
      print('File was not pcap format', end='\n', flush=True)
      sys.exit(1)
    for ts, buf in preader:
      try:
        counter = counter + 1
        ts = ts/1000000000

        (pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket) = packetType(buf)

        if tcpPacket and tcpCheck:
          [timeStamp, fingerprint] = satoriTCP.tcpProcess(pkt, layer, ts, pypackerVersion, sExactList, saExactList, sPartialList, saPartialList)
          printCheck(timeStamp, fingerprint)

        if dhcpPacket and dhcpCheck:
          [timeStamp, fingerprintOptions, fingerprintOption55, fingerprintVendorCode] = satoriDHCP.dhcpProcess(
                                 pkt, layer, ts, DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, 
                                 ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, 
                                 InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, 
                                 ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, 
                                 AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, 
                                 RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, 
                                 ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, 
                                 DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, 
                                 AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, 
                                 NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, 
                                 OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, 
                                 OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, 
                                 DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, 
                                 DeclineTTLExactList)
          printCheck(timeStamp, fingerprintOptions)
          printCheck(timeStamp, fingerprintOption55)
          printCheck(timeStamp, fingerprintVendorCode)
        if httpPacket and httpCheck:
          [timeStamp, fingerprintHdrUserAgent, fingerprintBodyUserAgent] = satoriHTTP.httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList)
          printCheck(timeStamp, fingerprintHdrUserAgent)
          printCheck(timeStamp, fingerprintBodyUserAgent)
          [timeStamp, fingerprintHdrServer, fingerprintBodyServer] = satoriHTTP.httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList)
          printCheck(timeStamp, fingerprintHdrServer)
          printCheck(timeStamp, fingerprintBodyServer)
#        if (eth[ethernet.Ethernet, ip.IP, icmp.ICMP] is not None) and icmpCheck:
#          satoriICMP.icmpProcess(eth, ts, icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList)
        if tcpPacket and smbCheck:
          [timeStamp, fingerprintOS, fingerprintLanMan] = satoriSMB.smbTCPProcess(pkt, layer, ts, nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList)
          printCheck(timeStamp, fingerprintOS)
          printCheck(timeStamp, fingerprintLanMan)
        if udpPacket and smbCheck:
          [timeStamp, fingerprint] = satoriSMB.smbUDPProcess(pkt, layer, ts, browserExactList, browserPartialList)
          printCheck(timeStamp, fingerprint)

      except (KeyboardInterrupt, SystemExit):
        raise
      except:
        pass


  elif interface != '':
    try:
      preader = pcapy.open_live(interface, 65536, False, 1)
      #highly recommended to add something like this for a bpf filter on a high throughput connection (4 Gb/s link script sorta died on me in testing)
      if len(filter) > 0:
        preader.setfilter(filter)
    except Exception as e:
      print(e, end='\n', flush=True)
      sys.exit(1)
    while True:
      try:
        counter = counter + 1
        (header, buf) = preader.next()
        ts = header.getts()[0]

        (pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket) = packetType(buf)

        if tcpPacket and tcpCheck:
          [timeStamp, fingerprint] = satoriTCP.tcpProcess(pkt, layer, ts, pypackerVersion, sExactList, saExactList, sPartialList, saPartialList)
          printCheck(timeStamp, fingerprint)
        if dhcpPacket and dhcpCheck:
          [timeStamp, fingerprintOptions, fingerprintOption55, fingerprintVendorCode] = satoriDHCP.dhcpProcess(
                                 pkt, layer, ts, DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, 
                                 ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, 
                                 InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, 
                                 ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, 
                                 AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, 
                                 RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, 
                                 ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, 
                                 DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, 
                                 AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, 
                                 NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, 
                                 OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, 
                                 OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, 
                                 DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, 
                                 DeclineTTLExactList)
          printCheck(timeStamp, fingerprintOptions)
          printCheck(timeStamp, fingerprintOption55)
          printCheck(timeStamp, fingerprintVendorCode)
        if httpPacket and httpCheck:
          [timeStamp, fingerprintHdrUserAgent, fingerprintBodyUserAgent] = satoriHTTP.httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList)
          printCheck(timeStamp, fingerprintHdrUserAgent)
          printCheck(timeStamp, fingerprintBodyUserAgent)
          [timeStamp, fingerprintHdrServer, fingerprintBodyServer] = satoriHTTP.httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList)
          printCheck(timeStamp, fingerprintHdrUserServer)
          printCheck(timeStamp, fingerprintBodyServer)
#        if (eth[ethernet.Ethernet, ip.IP, icmp.ICMP] is not None) and icmpCheck:
#          satoriICMP.icmpProcess(eth, ts, icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList)
        if tcpPacket and smbCheck:
          [timeStamp, fingerprintOS, fingerprintLanMan] = satoriSMB.smbTCPProcess(pkt, layer, ts, nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList)
          printCheck(timeStamp, fingerprintOS)
          printCheck(timeStamp, fingerprintLanMan)
        if udpPacket and smbCheck:
          [timeStamp, fingerprint] = satoriSMB.smbUDPProcess(pkt, layer, ts, browserExactList, browserPartialList)
          printCheck(timeStamp, fingerprint)
      except (KeyboardInterrupt, SystemExit):
        raise
      except:
        pass


  else:  #we should never get here with "proceed" check, but just in case
    print("Not sure how we got here", end='\n', flush=True)

  endTime = time.time()
  totalTime = endTime - startTime

  if verbose:
    print ('Total Time: %s, Total Packets: %s, Packets/s: %s' % (totalTime, counter, counter / totalTime ))

try:
  opts, args = getopt.getopt(sys.argv[1:], "r:m:i:l:v:d:f:", [ 'read=', 'modules=', 'interface=', 'limit=', 'verbose', 'directory=', 'filter=', 'version', 'dupes'])

  readpcap = interface = modules = limit = directory = filter = version = dupes = ''
  proceed = False
  verbose = False

  for opt, val in opts:
    if opt in ('--version'):
      versionInfo()
      sys.exit()
    if opt in ('--dupes'):
      satoriCommon.Dupes()
      sys.exit()
    if opt in ('-r', '--read'):
      if interface != '':
        print('\nCannot operate in interface and readpcap mode simultaneously, please select only one.')
        sys.exit()
      if not os.path.isfile(val):
        print('\nFile "%s" does not appear to exist, please verify pcap file name.' % val)
        sys.exit()
      else:
        proceed = True
        readpcap = val
    if opt in ('-m', '--modules'):
      modules = val
    if opt in ('-i', '--interface'):
      if readpcap != '':
        print('\nCannot operate in interface and readpcap mode simultaneously, please select only one.')
        sys.exit()
      interface = val
      proceed = True
    if opt in ('-l', '--limit'):
      if val.isnumeric(): 
        limit = val
      else:
        print ('\nLimitation: "%s" must be a number.' % val)
        sys.exit()
    if opt in ('-v', '--verbose'):
      verbose = True
    if opt in ('-d', '--directory'):
      if not os.path.isdir(val):
        print ('\nDir "%s" does not appear to exist, please verify directory name.' % val)
        sys.exit()
      else:
        proceed = True
        directory = val
    if opt in ('-f', '--filter'):
      if directory != '':
        print('Filter not implemented in directory processing, please remove and try again', end='\n', flush=True)
        sys.exit(1)
      if readpcap != '':
        print('Filter not implemented in pcap file read processing, please remove and try again', end='\n', flush=True)
        sys.exit(1)
      filter = val

  if limit == '':
    historyTime = 0
  else:
    historyTime = limit
  historyCheck = {}

  if (__name__ == '__main__') and proceed:
    main()
  else:
    print('Need to provide a pcap to read in or an interface to watch', end='\n', flush=True)
    usage()

except getopt.error:
     usage()



