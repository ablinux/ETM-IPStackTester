from scapy.all import *

RESULT = {
    0: "E_OK",
    1: "E_NOK",
    0xFF: "E_NTF",
    0xFE: "E_PEN",
    0xFD: "E_ISB",
    0xEF: "E_ISD",
    0xEE: "E_UCS",
    0xED: "E_UBS",
    0xEC: "E_INV"
}

PIDs = {
    0: "CLOSE_SOCKET",
    1: "CREATE_AND_BIND",
    2: "SEND_DATA",
    3: "RECEIVE_AND_FORWARD",
    4: "LISTEN_AND_ACCEPT",
    5: "CONNECT",
    6: "CONFIGURE_SOCKET",
    7: "SHUTDOWN"
}

GIDs = {
    0: "GENERAL",
    1: "UDP",
    2: "TCP",
    3: "ICMP",
    4: "ICMPv6",
    5: "IP"
}
'''
_______________________________________________________________________________________________________________________
Etm Packet
'''


class Etm(Packet):
    name = "Etm Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8)
                   # XBitField("DAT", 0, 40)
                   ]


'''
_______________________________________________________________________________________________________________________
Etm ICMPv6 Echo request
'''
class Etm_ICMPEchoRequest(Packet):
    name = "Etm ICMPv6 Echo request"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   # Interface Name --- begin
                   XBitField("if_name_len",0,16),
                   XBitField("BOM",0xEFBBBF,24),
                   StrLenField("if_name","HCP3_ETHIF_0"),
                   XBitField("text_termination", 0, 8),
                   # Interface Name --- End
                   XStrFixedLenField("destAddr", 0, 18),
                   XBitField("data_size",0x00,16),
                   StrLenField("data", "allohaa")
                   ]

'''
_______________________________________________________________________________________________________________________
Etm NDP Cache
'''


class Etm_NDPCache(Packet):
    name = "Etm Packet Etm_NDPCache"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("DAT", 0, 40)
                   ]
'''
_______________________________________________________________________________________________________________________
Etm PHY Signal Quality
'''
class Etm_PHYSignalQuality(Packet):
    name = "Etm Packet Phy Signal Quality"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   # # Text field is divided into 3 parts 1st complete test len field = BOM+Text+termination
                   # FieldLenField("ifname_full_len",None,length_of="ifName"),
                   # # 3rd actual text
                   # StrLenField("ifName","ABCDEFGH",length_from=lambda pkt:pkt.ifname_full_len)
                   XBitField("if_name_len",0,16),
                   XBitField("BOM",0xEFBBBF,24),
                   StrLenField("if_name","VLAN14"),
                   XBitField("text_termination", 0, 8),
                   ]

'''
_______________________________________________________________________________________________________________________
Etm PHY Signal Quality Response
'''
class Etm_Resp_PHYSignalQuality(Packet):
    name = "Etm Packet Phy Signal Quality"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("sigQuality",0,8)
                   ]

'''
_______________________________________________________________________________________________________________________
Etm PHY Read Diag result
'''
class Etm_PHYReadDiagResult(Packet):
    name = "Etm Packet Phy read diag result"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   # # Text field is divided into 3 parts 1st complete test len field = BOM+Text+termination
                   # FieldLenField("ifname_full_len",None,length_of="ifName"),
                   # # 3rd actual text
                   # StrLenField("ifName","ABCDEFGH",length_from=lambda pkt:pkt.ifname_full_len)
                   XBitField("if_name_len",0,16),
                   XBitField("BOM",0xEFBBBF,24),
                   StrLenField("if_name","VLAN14"),
                   XBitField("text_termination", 0, 8),
                   ]

'''
_______________________________________________________________________________________________________________________
Etm PHY Signal Quality Response
'''
class Etm_Resp_PHYReadDiagResult(Packet):
    name = "Etm Packet Phy read diag result response"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("diagResult",0,8)
                   ]

'''
_______________________________________________________________________________________________________________________
Etm PHY Activate PHY Test Mode
'''
class Etm_PHYActivateTestMode(Packet):
    name = "Etm Packet Phy Activate PHY Test Mode"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   # # Text field is divided into 3 parts 1st complete test len field = BOM+Text+termination
                   # FieldLenField("ifname_full_len",None,length_of="ifName"),
                   # # 3rd actual text
                   # StrLenField("ifName","ABCDEFGH",length_from=lambda pkt:pkt.ifname_full_len)
                   XBitField("if_name_len",0,16),
                   XBitField("BOM",0xEFBBBF,24),
                   StrLenField("if_name","VLAN14"),
                   XBitField("text_termination", 0, 8),
                   XBitField("testMode", 0x00, 8)
                   ]

'''
_______________________________________________________________________________________________________________________
Etm PHY Set PHY Tx Mode
'''
class Etm_PHYSetTxMode(Packet):
    name = "Etm Packet Phy Set PHY Tx Mode"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   # # Text field is divided into 3 parts 1st complete test len field = BOM+Text+termination
                   # FieldLenField("ifname_full_len",None,length_of="ifName"),
                   # # 3rd actual text
                   # StrLenField("ifName","ABCDEFGH",length_from=lambda pkt:pkt.ifname_full_len)
                   XBitField("if_name_len",0,16),
                   XBitField("BOM",0xEFBBBF,24),
                   StrLenField("if_name","VLAN14"),
                   XBitField("text_termination", 0, 8),
                   XBitField("txMode", 0x00, 8)
                   ]

'''
_______________________________________________________________________________________________________________________
Etm Packet resp version 
'''


class EtmRespVersion(Packet):
    name = "Etm Resp version Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("MajorVer", 0, 16),
                   XBitField("MinorVer", 0, 16)
                   ]


'''
_______________________________________________________________________________________________________________________
Etm Packet resp Create and bind
'''


class EtmRespCreateAndBind(Packet):
    name = "Etm Resp Create and bind"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("SocketId", 0, 16)
                   ]


'''
_______________________________________________________________________________________________________________________
Etm Packet request close socket
'''


class EtmReqSocketClose(Packet):
    name = "Etm Request close socket"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("socketId", 0, 16),
                   XBitField("abort", 0, 8)
                   ]


'''
_______________________________________________________________________________________________________________________
Etm Packet request send data
'''


class EtmReqSendData(Packet):
    name = "Etm Request send data at UDP"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("socketId", 0, 16),
                   XBitField("totalLen", 0, 16),
                   XBitField("destPort", 0, 16),
                   XStrFixedLenField("destAddr", 0, 18),
                   XBitField("varDataLen",0,16),
                   XStrFixedLenField("Data", 0, 36)
                   ]

'''
_______________________________________________________________________________________________________________________
Etm Packet request send data
'''


class EtmReqSendData_tcp(Packet):
    name = "Etm Request send data at TCP"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("socketId", 0, 16),
                   XBitField("totalLen", 0, 16),
                   XBitField("flags",0x8,8),
                   XBitField("varDataLen",0,16),
                   XStrFixedLenField("Data", 0, 36)
                   ]


'''
_______________________________________________________________________________________________________________________
Etm Packet Create and bind
'''


class Etm_CreateBind(Packet):
    name = "Etm Create and Bind Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("doBind", 0x1, 8),
                   XBitField("localPort", 0xFFFF, 16),
                   XStrFixedLenField("localAddr", 0xDEADBEEF, 18)
                   ]


'''
_______________________________________________________________________________________________________________________
Etm Packet Receive and forward
'''


class Etm_ReceiveAndFwd(Packet):
    name = "Etm Create and Bind Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("socketId", 0x0, 16),
                   XBitField("maxFwd", 0xFFFF, 16),
                   XBitField("maxLen", 0xFFFF, 16),
                   ]

'''
_______________________________________________________________________________________________________________________
Etm Packet TCP Connect
'''


class Etm_TCPConnect(Packet):
    name = "Etm tcp connect Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x02, 7),
                   XBitField("PID", 0x05, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("socketId", 0x0, 16),
                   XBitField("destPort", 0x0, 16),
                   XStrFixedLenField("destAddress", 0x0, 18),
                   ]

'''
_______________________________________________________________________________________________________________________
Etm Shutdown packet
'''


class Etm_ShutDown(Packet):
    name = "Etm shut down Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x02, 7),
                   XBitField("PID", 0x05, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("socketId", 0x0, 16),
                   XBitField("typeid", 0x0, 16),
                   ]

'''
_______________________________________________________________________________________________________________________
Etm listen and accept packet
'''


class Etm_ListenAcceptPacket(Packet):
    name = "Etm listen and accept Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x02, 7),
                   XBitField("PID", 0x05, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("listenSocketId", 0x0, 16),
                   XBitField("maxCon", 0x0, 16),
                   ]

'''
_______________________________________________________________________________________________________________________
Etm Packet Configure Socket
'''


class Etm_ConfigureSocket(Packet):
    name = "Etm Configure soket Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x00, 7),
                   XBitField("PID", 0x00, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("socketId", 0x0, 16),
                   XBitField("paramId", 0x0, 16),
                   XBitField("varDataLen", 0, 16),
                   XBitField("paramVal", 0x0, 8),
                   ]

'''
_______________________________________________________________________________________________________________________
Etm Packet Receive and forward response
'''


class Etm_RespReceiveAndFwd(Packet):
    name = "Etm Create and Bind Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("dropCnt", 0x0, 16),
                   ]


'''
_______________________________________________________________________________________________________________________
Etm Packet Receive and forward response
'''


class Etm_RespEventReceiveAndFwd(Packet):
    name = "Etm Create and Bind Packet"
    fields_desc = [XBitField("ServiceId", 0x0105, 16),
                   XBitField("EVB", 0, 1),
                   XBitField("GID", 0x01, 7),
                   XBitField("PID", 0x01, 8),
                   XBitField("Length", 16, 32),
                   XBitField("DontCare", 0, 32),
                   XBitField("ProtoVersion", 0x01, 8),
                   XBitField("IfaceVersion", 0x01, 8),
                   XBitField("TID", 0, 8),
                   XBitField("RID", 0, 8),
                   XBitField("fullLen", 0x0, 16),
                   XBitField("srcPort", 0x0, 16),
                   XBitField("ipVer", 0, 16),
                   XStrFixedLenField("srcAddr", 0x0, 16),
                   StrField("payload", 32),

                   ]
