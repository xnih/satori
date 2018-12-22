from pypacker import pypacker, triggerlist
import struct
import untangle

#from pypacker.structcbs import unpack_B
# https://docs.python.org/3.1/library/struct.html#format-characters
#import logging

class netbiosSessionService(pypacker.Packet):
  __hdr__ = [
    ("msgtype", "B", 0),
    ("len", "3s", b"")
  ]


class negotiateProtocol(pypacker.Packet):   #0x72
#mss = struct.unpack('!h',i.body_bytes)[0]
  __hdr__ = [
    ("wordcount", "B", 0),
    ("bytecount", "H", 0),
  ]

class UDPSMB_Header(pypacker.Packet):
  __hdr__ = [
    ("component", "4s", b""),
    ("command", "B", 0),
    ("errorClass", "B", 0),
    ("reserved", "B", 0),
    ("errorCode", "H", 0),
    ("flags", "B", 0),
    ("flags2", "H", 0),
    ("processIDHigh", "H", 0),
    ("signature", "8s", b""),
    ("reserved2", "H", 0),
    ("treeID", "H", 0),
    ("processID", "H", 0),
    ("userID", "H", 0),
    ("multiplexID", "H", 0),
  ]

class NBDS_Header(pypacker.Packet):
  __hdr__ = [
    ("msgType", "B", 0),
    ("flags", "B", 0),
    ("datagramID", "H", 0),
    ("sourceIP", "4s", b""),
    ("sourcePort", "H", 0),
    ("datagramLen", "H", 0),
    ("packetOffset", "H", 0),
    ("sourceName", "34s", b""),
    ("destName", "34s", b"")
  ]

class SMBMailSlot_Header(pypacker.Packet):
  __hdr__ = [
    ("opcode", "H", 0),
    ("priority", "H", 0),
    ("class", "H", 0),
    ("length", "H", 0)
  ]

class transRequest_Header(pypacker.Packet):  #0x25
  __hdr__ = [
    ("wordCount", "B", 0),
    ("totalParamCount", "H", 0),
    ("totalDataCount", "H", 0),
    ("maxParamCount", "H", 0),
    ("maxDataCount", "H", 0),
    ("maxSetupCount", "B", 0),
    ("reserved", "B", 0),
    ("flags", "H", 0),
    ("timeout", "4s", b""),
    ("reserved2", "H", 0),
    ("paramCount", "H", 0),
    ("paramOffset", "H", 0),
    ("dataCount", "H", 0),
    ("dataOffset", "H", 0),
    ("setupCount", "B", 0),
    ("reserved3", "B", 0)
  ]

class MWBP_HostAnnounce(pypacker.Packet):   #0x01
  __hdr__ = [
    ("command", "B", 0),
    ("updateCount", "B", 0),
    ("updatePeriod", "4s", b""),
    ("hostName", "16s", b""),
    ("osMajorVer", "B", 0),
    ("osMinVer", "B", 0),
    ("serverType", "4s", b""),
    ("browMajorVer", "B", 0),
    ("browMinVer", "B", 0),
    ("signature", "H", 0),
#    ("comment", "256s", b"")
  ]

"""
  MWBP_WorkGroupAnnounce = packed record
    UpdateCount    :uchar;
    UpdatePeriod   :dword;
    Workgroup      :array[0 .. 15] of char;
    OSMajorVer     :uchar;
    OSMinorVer     :uchar;
    ServerType     :dword;
    MysteryField   :dword;
//master browser, multilength, seems to be same as hostname, so ignoring for now
  end;
"""


class tcpSMB(pypacker.Packet):
#https://msdn.microsoft.com/en-us/library/ee441774.aspx
  __hdr__ = [
    ("proto", "I", 0),
    ("cmd", "B", 0),
    ("status", "I", 0),
    ("flags", "B", 0),
    ("flags2", "2s", b""),
    ("processIDHigh", "H", 0),  #2s
#    ("signature", "Q", b""),  #8s
    ("key", "4s", b""),
    ("cid", "H", 0),
    ("seqnum", "H", 0),
    ("reserved", "H", 0),
    ("tid", "H", 0),
    ("pid", "H", 0),
    ("uid", "H", 0),
    ("mid", "H", 0)
  ]


# word = H
# uchar = B
# dword = 4s

class SSAndRequestHeader_w3(pypacker.Packet):
#  { SMB Command = 0x73 and SMB Flag 1 and wordcount = 3}
  __hdr__ = [
    ("WordCount", "B", 0),
    ("AndXCommand", "B", 0),
    ("Reserved", "B", 0),
    ("AndXOffset", "H", 0),
    ("Action", "H", 0),
    ("ByteCount", "H", 0)
  ]


class SSAndRequestHeader_w4(pypacker.Packet):
#  { SMB Command = 0x73 and wordcount = 4}
  __hdr__ = [
    ("WordCount", "B", 0),
    ("AndXCommand", "B", 0),
    ("Reserved", "B", 0),
    ("AndXOffset", "H", 0),
    ("Action", "2s", b""),
    ("SecurityBlobLen", "2s", b""),
    ("ByteCount", "H", 0)
  ]


class SSAndRequestHeader_w12(pypacker.Packet):
#  { SMB Command = 0x73 and SMB Flag 0 wordcount = 12}
  __hdr__ = [
    ("WordCount", "B", 0),
    ("AndXCommand", "B", 0),
    ("Reserved", "B", 0),
    ("AndXOffset", "H", 0),
    ("MaxBuffer", "2s", b""),
    ("MaxMPXCount", "H", 0),
    ("VCNumber", "H", 0),
    ("SessionKey", "4s", b""),
    ("SecurityBlobLen", "2s", b""),
    ("Reserved2", "4s", b""),
    ("Capabilities", "4s", b""),
    ("ByteCount", "H", 0)
  ]

class SSAndRequestHeader_w13(pypacker.Packet):
#  { SMB Command = 0x73 and SMB Flag 0 wordcount = 13}
  __hdr__ = [
    ("WordCount", "B", 0),
    ("AndXCommand", "B", 0),
    ("Reserved", "B", 0),
    ("AndXOffset", "H", 0),
    ("MaxBuffer", "H", 0),
    ("MaxMPXCount", "H", 0),
    ("VCNumber", "H", 0),
    ("SessionKey", "4s", b""),
    ("ANSIPasswordLen", "2s", b""),
    ("UniCodePassLen", "2s", b""),
    ("Reserved2", "4s", b""),
    ("Capabilities", "4s", b""),
    ("ByteCount", "H", 0),
  ]


class SSAndResponse_Header(pypacker.Packet):
#  { SMB Command = 0x73 and SMB Flag 1 and wordcount = 4}
  __hdr__ = [
    ("WordCount", "B", 0),
    ("AndXCommand", "B", 0),
    ("Reserved", "B", 0),
    ("AndXOffset", "H", 0),
    ("Action", "H", 0),
    ("SecurityBlobLen", "H", 0),
    ("ByteCount", "H", 0)
  ]

# good starting point  https://github.com/SpiderLabs/Responder/blob/master/packets.py
"""
my pascal code to convert


  NBSS_Header = packed record
    MsgType       :uchar;
    Length        :array[0..2] of Byte;
  end;

  UDPSMB_Header = packed record
    ServerComponent:dword;
    Command        :uchar;
    ErrorClass     :uchar;
    Reserved       :uchar;
    Error          :word;
    flags          :uchar;
    flags2         :word;
    ProcessIDHigh  :word;
    Signature      :array[0 .. 7] of char;
    Reserved2      :word;
    TreeID         :word;
    ProcessID      :word;
    UserID         :word;
    MultiplexID    :word;
  end;

  MWBP_HostAnnounce = packed record
    UpdateCount    :uchar;
    UpdatePeriod   :dword;
    HostName       :array[0 .. 15] of char;
    OSMajorVer     :uchar;
    OSMinorVer     :uchar;
    ServerType     :dword;
    BrowMajVer     :uchar;
    BrowMinVer     :uchar;
    Signature      :word;
    Comment        :array[0 .. 255] of char;
  end;

  MWBP_WorkGroupAnnounce = packed record
    UpdateCount    :uchar;
    UpdatePeriod   :dword;
    Workgroup      :array[0 .. 15] of char;
    OSMajorVer     :uchar;
    OSMinorVer     :uchar;
    ServerType     :dword;
    MysteryField   :dword;
//master browser, multilength, seems to be same as hostname, so ignoring for now
  end;

"""
