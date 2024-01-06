from pypacker.layer12 import ethernet, linuxcc
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import tcp, udp, ssl
from pypacker.layer567 import dhcp, http, dns, ntp
from pypacker import pypacker, ppcap
import datetime
try:
  import pcapy
except:
  import pcapyplus as pcapy
import argparse
import time
import sys
import os
import satoriTCP
import satoriDHCP
import satoriHTTP
#import satoriICMP
import satoriSMB
import smbHeader
import satoriCommon
import satoriSSL
import satoriDNS
import satoriNTP
import satoriSSH


def versionInfo():
  dateReleased='satori.py - 2024-01-06'
  print(dateReleased)
  satoriTCP.version()
  satoriDHCP.version()
  satoriHTTP.version()
  satoriSMB.version()
  satoriSSL.version()
  satoriDNS.version()
  satoriNTP.version()
  satoriSSH.version()
  satoriCommon.version()
  satoriCommon.getImportVersions()


def packetType(buf):
  tcpPacket = False
  dhcpPacket = False
  httpPacket = False
  udpPacket = False
  sslPacket = False
  smbPacket = False
  dnsPacket = False
  ntpPacket = False
  sshPacket = False
  quicPacket = False

  #try to determine what type of packets we have, there is the chance that 0x800 may be in the spot we're checking, may want to add better testing in future
  eth = ethernet.Ethernet(buf)
  if hex(eth.type) == '0x800':
    layer = 'eth'
    pkt = eth

    if (eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None):
      if eth[tcp.TCP] != None:
        tcpPacket = True
        if (eth[ethernet.Ethernet, ip.IP, tcp.TCP, ssl.SSL] is not None):
          if eth[ssl.SSL] != None:
            sslPacket = True
        if (eth[ethernet.Ethernet, ip.IP, tcp.TCP, http.HTTP] is not None):
          if eth[http.HTTP] != None:
            httpPacket = True
        if (eth[ethernet.Ethernet, ip.IP, tcp.TCP, dns.DNS] is not None):
          if eth[dns.DNS] != None:
            dnsPacket = True
        #attempt to tell if it is SMB, kludgy!
        tcp1 = eth[ip.IP].upper_layer
        if (tcp1.sport == 138) or (tcp1.dport == 138) or (tcp1.sport == 139) or (tcp1.dport == 138) or (tcp1.sport == 445) or (tcp1.dport == 445):
          smbPacket = True
        #attempt to tell if it is SSH, kludgy!
        try:
          if 'SSH' in tcp1.body_bytes.decode("utf-8"):
            sshPacket = True
        except:
          pass

    if (eth[ethernet.Ethernet, ip.IP, udp.UDP] is not None):
      if eth[udp.UDP] != None:
        udpPacket = True
        if (eth[ethernet.Ethernet, ip.IP, udp.UDP, dhcp.DHCP] is not None):
          if eth[dhcp.DHCP] != None:
            dhcpPacket = True
        if (eth[ethernet.Ethernet, ip.IP, udp.UDP, dns.DNS] is not None):
          if eth[dns.DNS] != None:
            dnsPacket = True
        if (eth[ethernet.Ethernet, ip.IP, udp.UDP, ntp.NTP] is not None):
          if eth[ntp.NTP] != None:
            ntpPacket = True
        #attempt to tell if it is SMB, kludgy!
        udp1 = eth[ip.IP].upper_layer
        if (udp1.sport == 138) or (udp1.dport == 138) or (udp1.sport == 139) or (udp1.dport == 138) or (udp1.sport == 445) or (udp1.dport == 445):
          smbPacket = True
        #attempt to tell if it is quic, kludgy!
        if (udp1.dport == 443):
          quicPacket = True


  lcc = linuxcc.LinuxCC(buf)
  if hex(lcc.type) == '0x800':
    layer = 'lcc'
    pkt = lcc

    if (lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP] is not None):
      if lcc[tcp.TCP] != None:
        tcpPacket = True
        if (lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP, ssl.SSL] is not None):
          if lcc[ssl.SSL] != None:
            sslPacket = True
        if (lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP, http.HTTP] is not None):
          if lcc[http.HTTP] != None:
            httpPacket = True
        if (lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP, dns.DNS] is not None):
          if lcc[dns.DNS] != None:
            dnsPacket = True
        #attempt to tell if it is SMB, kludgy!  For TCP I probably only need 139 and 445
        tcp1 = lcc[ip.IP].upper_layer
        if (tcp1.sport == 138) or (tcp1.dport == 138) or (tcp1.sport == 139) or (tcp1.dport == 138) or (tcp1.sport == 445) or (tcp1.dport == 445):
          smbPacket = True
        #attempt to tell if it is SSH, kludgy!
        try:
          if 'SSH' in tcp1.body_bytes.decode("utf-8"):
            sshPacket = True
        except:
          pass

    if (lcc[linuxcc.LinuxCC, ip.IP, udp.UDP] is not None):
      if lcc[udp.UDP] != None:
        udpPacket = True
        if (lcc[linuxcc.LinuxCC, ip.IP, udp.UDP, dhcp.DHCP] is not None):
          if lcc[dhcp.DHCP] != None:
            dhcpPacket = True
        if (lcc[linuxcc.LinuxCC, ip.IP, udp.UDP, dns.DNS] is not None):
          if lcc[dns.DNS] != None:
            dnsPacket = True
        if (lcc[linuxcc.LinuxCC, ip.IP, udp.UDP, ntp.NTP] is not None):
          if lcc[ntp.NTP] != None:
            dnsPacket = True
        #attempt to tell if it is SMB, kludgy!  For UDP I probably only need 138
        udp1 = lcc[ip.IP].upper_layer
        if (udp1.sport == 138) or (udp1.dport == 138) or (udp1.sport == 139) or (udp1.dport == 138) or (udp1.sport == 445) or (udp1.dport == 445):
          smbPacket = True
        #attempt to tell if it is quic, kludgy!
        if (udp1.dport == 443):
          quicPacket = True

  return(pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket, sslPacket, smbPacket, dnsPacket, ntpPacket, quicPacket, sshPacket)


def printCheck(timeStamp, fingerprint):

  if fingerprint != None:
    if historyTime != 0:
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

  #some verbose vars
  counter = 0
  startTime = time.time()

  #general vars
  tcpCheck = False
  dhcpCheck = False
  httpCheck = False
  icmpCheck = False  #not enabled in lower code at this point due to tracking features I'm not willing to code at this time.
  smbCheck = False
  sslCheck = False
  dnsCheck = False
  ntpCheck = False
  sshCheck = False

  #read in fingerprints
  [sslJA3XMLExactList, sslJA3SXMLExactList, sslJA3JSONExactList, sslJA4XMLExactList] = satoriSSL.BuildSSLFingerprintFiles()
  [sExactList, saExactList, sPartialList, saPartialList] = satoriTCP.BuildTCPFingerprintFiles()
  [DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, DeclineTTLExactList] = satoriDHCP.BuildDHCPFingerprintFiles()
  [useragentExactList, useragentPartialList] = satoriHTTP.BuildHTTPUserAgentFingerprintFiles()
  [serverExactList, serverPartialList] = satoriHTTP.BuildHTTPServerFingerprintFiles()
  #[icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList] = satoriICMP.BuildICMPFingerprintFiles()
  [nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList] = satoriSMB.BuildSMBTCPFingerprintFiles()
  [browserExactList, browserPartialList] = satoriSMB.BuildSMBUDPFingerprintFiles()
  [dnsExactList, dnsPartialList] = satoriDNS.BuildDNSFingerprintFiles()
  [ntpExactList, ntpPartialList] = satoriNTP.BuildNTPFingerprintFiles()
  [sshExactList, sshPartialList] = satoriSSH.BuildSSHFingerprintFiles()

  #check pypacker version due to changes between 4.9 and 5.0 for one TCP feature
  pypackerVersion = satoriCommon.checkPyPackerVersion()

  if len(modules) == 0:
    tcpCheck = True
    dhcpCheck = True
    httpCheck = True
    icmpCheck = True
    smbCheck = True
    sslCheck = True
    ntpCheck = True
    dnsCheck = True
    sshCheck = True
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
      elif (mod[i].lower() == 'ssl'):
        sslCheck = True
      elif (mod[i].lower() == 'dns'):
        dnsCheck = True
      elif (mod[i].lower() == 'ntp'):
        ntpCheck = True
      elif (mod[i].lower() == 'ssh'):
        sshCheck = True

  if (directory != ''):  #probably a better way to do this and dupe most of the below code from preader section, but DHCP passing parameters into a procedure sucks.
    onlyfiles = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    for f in onlyfiles:
      try:
        preader = ppcap.Reader(filename=directory + '/' + f)

        for ts, buf in preader:
          try:
            counter = counter + 1
            ts = ts/1000000000

            (pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket, sslPacket, smbPacket, dnsPacket, ntpPacket, quicPacket, sshPacket) = packetType(buf)

            try:
              if tcpPacket and tcpCheck:
                [timeStamp, fingerprint] = satoriTCP.tcpProcess(pkt, layer, ts, pypackerVersion, sExactList, saExactList, sPartialList, saPartialList)
                printCheck(timeStamp, fingerprint)
            except:
              pass

            try:
              if sslPacket and sslCheck:
                [timeStamp, fingerprints] = satoriSSL.sslProcess(pkt, layer, ts, sslJA3XMLExactList, sslJA3SXMLExactList, sslJA3JSONExactList, sslJA4XMLExactList)
                for fingerprint in fingerprints:
                  printCheck(timeStamp, fingerprint)
            except:
              pass

            try:
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
            except:
              pass

            try:
              if httpPacket and httpCheck:
                [timeStamp, fingerprintHdrUserAgent, fingerprintBodyUserAgent] = satoriHTTP.httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList)
                printCheck(timeStamp, fingerprintHdrUserAgent)
                printCheck(timeStamp, fingerprintBodyUserAgent)
                [timeStamp, fingerprintHdrServer, fingerprintBodyServer] = satoriHTTP.httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList)
                printCheck(timeStamp, fingerprintHdrServer)
                printCheck(timeStamp, fingerprintBodyServer)
            except:
              pass

#            try:
#              if (eth[ethernet.Ethernet, ip.IP, icmp.ICMP] is not None) and icmpCheck:
#                satoriICMP.icmpProcess(eth, ts, icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList)
#            except:
#              pass

            try:
              if tcpPacket and smbPacket and smbCheck:
                [timeStamp, fingerprintOS, fingerprintLanMan] = satoriSMB.smbTCPProcess(pkt, layer, ts, nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList)
                printCheck(timeStamp, fingerprintOS)
                printCheck(timeStamp, fingerprintLanMan)
            except:
              pass

            try:
              if udpPacket and smbPacket and smbCheck:
                [timeStamp, fingerprint] = satoriSMB.smbUDPProcess(pkt, layer, ts, browserExactList, browserPartialList)
                printCheck(timeStamp, fingerprint)
            except:
              pass

            try:
              if dnsPacket and dnsCheck:
                [timeStamp, fingerprint] = satoriDNS.dnsProcess(pkt, layer, ts, dnsExactList, dnsPartialList)
                printCheck(timeStamp, fingerprint)
            except:
              pass

            try:
              if ntpPacket and ntpCheck:
                [timeStamp, fingerprint] = satoriNTP.ntpProcess(pkt, layer, ts, ntpExactList, ntpPartialList)
                printCheck(timeStamp, fingerprint)
            except:
              pass

            try:
              if sshPacket and sshCheck:
                [timeStamp, fingerprint] = satoriSSH.sshProcess(pkt, layer, ts, sshExactList, sshPartialList)
                printCheck(timeStamp, fingerprint)
            except:
              pass

          except (KeyboardInterrupt, SystemExit):
            raise
          except ValueError as e:
            pass
          except Exception as e:
            pass
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
        (pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket, sslPacket, smbPacket, dnsPacket, ntpPacket, quicPacket, sshPacket) = packetType(buf)

        try:
          if tcpPacket and tcpCheck:
            [timeStamp, fingerprint] = satoriTCP.tcpProcess(pkt, layer, ts, pypackerVersion, sExactList, saExactList, sPartialList, saPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

        try:
          if sslPacket and sslCheck:
            [timeStamp, fingerprints] = satoriSSL.sslProcess(pkt, layer, ts, sslJA3XMLExactList, sslJA3SXMLExactList, sslJA3JSONExactList, sslJA4XMLExactList)
            for fingerprint in fingerprints:
              printCheck(timeStamp, fingerprint)
        except:
          pass

#        try:
#          if quicPacket and sslCheck:
#            [timeStamp, fingerprints] = satoriSSL.quicProcess(pkt, layer, ts, sslJA4XMLExactList)
#            for fingerprint in fingerprints:
#              printCheck(timeStamp, fingerprint)
#        except:
#          pass

        try:
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
        except:
          pass

        try:
          if httpPacket and httpCheck:
            [timeStamp, fingerprintHdrUserAgent, fingerprintBodyUserAgent] = satoriHTTP.httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList)
            printCheck(timeStamp, fingerprintHdrUserAgent)
            printCheck(timeStamp, fingerprintBodyUserAgent)
            [timeStamp, fingerprintHdrServer, fingerprintBodyServer] = satoriHTTP.httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList)
            printCheck(timeStamp, fingerprintHdrServer)
            printCheck(timeStamp, fingerprintBodyServer)
        except:
          pass

#        try:
#          if (eth[ethernet.Ethernet, ip.IP, icmp.ICMP] is not None) and icmpCheck:
#            satoriICMP.icmpProcess(eth, ts, icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList)
#        except:
#          pass

        try:
          if tcpPacket and smbPacket and smbCheck:
            [timeStamp, fingerprintOS, fingerprintLanMan] = satoriSMB.smbTCPProcess(pkt, layer, ts, nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList)
            printCheck(timeStamp, fingerprintOS)
            printCheck(timeStamp, fingerprintLanMan)
        except Exception as e:
          pass
        except:
          pass

        try:
          if udpPacket and smbPacket and smbCheck:
            [timeStamp, fingerprint] = satoriSMB.smbUDPProcess(pkt, layer, ts, browserExactList, browserPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

        try:
          if dnsPacket and dnsCheck:
            [timeStamp, fingerprint] = satoriDNS.dnsProcess(pkt, layer, ts, dnsExactList, dnsPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

        try:
          if ntpPacket and ntpCheck:
            [timeStamp, fingerprint] = satoriNTP.ntpProcess(pkt, layer, ts, ntpExactList, ntpPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

        try:
          if sshPacket and sshCheck:
            [timeStamp, fingerprint] = satoriSSH.sshProcess(pkt, layer, ts, sshExactList, sshPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

      except (KeyboardInterrupt, SystemExit):
        raise
      except ValueError as e:
        pass
      except Exception as e:
        pass
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
        (pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket, sslPacket, smbPacket, dnsPacket, ntpPacket, quicPacket, sshPacket) = packetType(buf)

        try:
          if tcpPacket and tcpCheck:
            [timeStamp, fingerprint] = satoriTCP.tcpProcess(pkt, layer, ts, pypackerVersion, sExactList, saExactList, sPartialList, saPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

        try:
          if sslPacket and sslCheck:
            [timeStamp, fingerprints] = satoriSSL.sslProcess(pkt, layer, ts, sslJA3XMLExactList, sslJA3SXMLExactList, sslJA3JSONExactList, sslJA4XMLExactList)
            for fingerprint in fingerprints:
              printCheck(timeStamp, fingerprint)
        except:
          pass

#        try:
#          if quicPacket and sslCheck:
#            [timeStamp, fingerprints] = satoriSSL.quicProcess(pkt, layer, ts, sslJA4XMLExactList)
#            for fingerprint in fingerprints:
#              printCheck(timeStamp, fingerprint)
#        except:
#          pass

        try:
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
        except:
          pass

        try:
          if httpPacket and httpCheck:
            [timeStamp, fingerprintHdrUserAgent, fingerprintBodyUserAgent] = satoriHTTP.httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList)
            printCheck(timeStamp, fingerprintHdrUserAgent)
            printCheck(timeStamp, fingerprintBodyUserAgent)
            [timeStamp, fingerprintHdrServer, fingerprintBodyServer] = satoriHTTP.httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList)
            printCheck(timeStamp, fingerprintHdrServer)
            printCheck(timeStamp, fingerprintBodyServer)
        except:
          pass

#        try:
#          if (eth[ethernet.Ethernet, ip.IP, icmp.ICMP] is not None) and icmpCheck:
#            satoriICMP.icmpProcess(eth, ts, icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList)
#        except:
#          pass


        try:
          if tcpPacket and smbPacket and smbCheck:
            [timeStamp, fingerprintOS, fingerprintLanMan] = satoriSMB.smbTCPProcess(pkt, layer, ts, nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList)
            printCheck(timeStamp, fingerprintOS)
            printCheck(timeStamp, fingerprintLanMan)
        except:
          pass

        try:
          if udpPacket and smbPacket and smbCheck:
            [timeStamp, fingerprint] = satoriSMB.smbUDPProcess(pkt, layer, ts, browserExactList, browserPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

        try:
          if dnsPacket and dnsCheck:
            [timeStamp, fingerprint] = satoriDNS.dnsProcess(pkt, layer, ts, dnsExactList, dnsPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

        try:
          if ntpPacket and ntpCheck:
            [timeStamp, fingerprint] = satoriNTP.ntpProcess(pkt, layer, ts, ntpExactList, ntpPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

        try:
          if sshPacket and sshCheck:
            [timeStamp, fingerprint] = satoriSSH.sshProcess(pkt, layer, ts, sshExactList, sshPartialList)
            printCheck(timeStamp, fingerprint)
        except:
          pass

      except (KeyboardInterrupt, SystemExit):
        raise
      except ValueError as e:
        pass
      except Exception as e:
        pass
      except:
        pass

  else:  #we should never get here with "proceed" check, but just in case
    print("Not sure how we got here", end='\n', flush=True)

  endTime = time.time()
  totalTime = endTime - startTime

  if verbose:
    print ('Total Time: %s, Total Packets: %s, Packets/s: %s' % (totalTime, counter, counter / totalTime ))


## Parse Arguments
try:
  historyTime = 0
  historyCheck = {}
  readpcap = interface = modules = limit = directory = filter = version = dupes = ''
  verbose = False
  proceed = False

  parser = argparse.ArgumentParser(prog='Satori')
  parser.add_argument('-d', '--directory', action="store", dest="directory", help="directory to read all pcaps in (does NOT do sub directories); example: -d /pcaps", default="")
  parser.add_argument('-r', '--read', action="store", dest="readpcap", help="pcap to read in; example: -r tcp.pcap", default="")
  parser.add_argument('-i', '--interface', action="store", dest="interface", help="interface to listen to; example: -i eth0", default="")
  parser.add_argument('-m', '--modules', action="store", dest="modules", help="modules to load; example: -m tcp,dhcp,smb,http", default="")
  parser.add_argument('-f', '--filter', action="store", dest="filter", help="bpf filter to apply (only implemented in live capture processing); example: -f \"tcp port 80 or tcp port 8080\"", default="")
  parser.add_argument('-l', '--limit', type=int, action="store", dest="limit", help="limit the number of same events written in a time period (in minutes); example -l 1", default=0)
  parser.add_argument('-v', '--verbose', action="store_true", dest="verbose", help="verbose logging, mostly just telling you where/what we're doing, not recommended if want to parse output typically", default=False)
  parser.add_argument('--version', action="store_true", dest="version", help="print dates for the different modules and 3rd party tools used", default="")
  parser.add_argument('--dupes', action="store_true", dest="dupes", help="check for dupes in the fingerprint files", default="")
  parser.add_argument('--ja3update', action="store_true", dest="ja3update", help="download latest ja3er.com json fingerprint file", default="")
  parser.add_argument('--trisulnsm', action="store_true", dest="trisulnsm", help="download latest trisulnsm json fingerprint file", default="")

  args = parser.parse_args()

  if args.readpcap != '':
    if args.interface != '':
      print('\nCannot operate in interface and readpcap mode simultaneously, please select only one.')
      sys.exit()
    if not os.path.isfile(args.readpcap):
      print('\nFile "%s" does not appear to exist, please verify pcap file name.' % args.readpcap)
      sys.exit()
    else:
      proceed = True
      readpcap = args.readpcap
  if args.modules != '':
    modules = args.modules
  if args.interface != '':
    if args.readpcap != '':
      print('\nCannot operate in interface and readpcap mode simultaneously, please select only one.')
      sys.exit()
    interface = args.interface
    proceed = True
  if args.limit != 0:
    historyTime = args.limit
  if args.verbose:
    verbose = True
  if args.directory != '':
    if not os.path.isdir(args.directory):
      print ('\nDir "%s" does not appear to exist, please verify directory name.' % args.directory)
      sys.exit()
    else:
      proceed = True
      directory = args.directory
  if args.filter != '':
    if args.directory != '':
      print('Filter not implemented in directory processing, please remove and try again', end='\n', flush=True)
      sys.exit(1)
    if args.readpcap != '':
      print('Filter not implemented in pcap file read processing, please remove and try again', end='\n', flush=True)
      sys.exit(1)
    filter = args.filter
  if args.version:
    versionInfo()
    sys.exit()
  if args.dupes:
    satoriCommon.Dupes()
    sys.exit()
  if args.ja3update:
    satoriSSL.ja3erUpdate()
    sys.exit()
  if args.trisulnsm:
    satoriSSL.trisulnsmUpdate()
    sys.exit()

  if (__name__ == '__main__') and proceed:
    main()
  else:
    print('Need to provide a pcap to read in, a directory to read, or an interface to watch!', end='\n', flush=True)
    parser.print_help()

except argparse.ArgumentError:
  print(self)
