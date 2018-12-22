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


#72 is worthless to me, just look at 73.


class negotiateProtocol(pypacker.Packet):
#mss = struct.unpack('!h',i.body_bytes)[0]
  __hdr__ = [
    ("wordcount", "B", 0),
    ("bytecount", "H", 0),
  ]


"""
  def _dissect(self, buf):
#    bytecount = buf[1:3]
    self._init_triggerlist("dialects", buf[4:], self._parse_dialects)
#    return hex(bytecount)


  @staticmethod
  def _parse_dialects(buf):
    optlist = []
    i = 0
    p = ''

    print(buf)
    while i < len(buf):
      if buf[i] != 0x00:
        p = p + str(buf[i])
      else:
       optlist.append(p)
#       print(p)
       p = ''
      i += 1
    print (optlist)
    return optlist
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


NBDS_Header = packed record
    MsgType       :uchar;
    NodeType      :uchar;
    DatagramID    :word;
    SourceIP      :array[0..3] of Byte;
    SourcePort    :word;
    DatagramLen   :word;
    PacketOffset  :word;
    SourceName    :QueryName;
    DestName      :QueryName;
  end;

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

  TCPSMB_Header = packed record
    ServerComponent:dword;
    Command        :uchar;
    Status         :dword;
    flags          :uchar;
    flags2         :word;
    ProcessIDHigh  :word;
    Signature      :array[0 .. 7] of char;
    Reserved       :word;
    TreeID         :word;
    ProcessID      :word;
    UserID         :word;
    MultiplexID    :word;
  end;

  MAILSLOT_Header = packed record
    opcode        :word;
    priority      :word;
    MSClass       :word;
    Length        :word;
  end;

  TRANSRQST_Header = packed record       //0x25
    WordCount      :uchar;
    TotalParmCount :word;
    TotalDataCount :word;
    MaxParmCount   :word;
    MaxDataCount   :word;
    MaxSetupCount  :uchar;
    Reserved1      :uchar;
    Flags          :word;
    Timeout        :dword;
    Reserved2      :word;
    ParamCount     :word;
    ParamOffset    :word;
    DataCount      :word;
    DataOffset     :word;
    SetupCount     :uchar;
    Reserved3      :uchar;
    MailProtocol   :MailSlot_Header;
  end;


  {smb command = 0x72}
  NegotiateProtocol_Header = packed record
    WordCount:uchar;
    ByteCount:word;
    //buffer of length bytecount needed
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
