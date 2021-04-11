import ipaddress
from PyQt5.QtWidgets import QFileDialog
from scapy.all import *
import psutil
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from PyQt5.QtGui import  QColor
from PyQt5 import QtGui, QtWidgets
from EtmTester import Ui_LowerTester
import EtmPackets

RESULT = {
    0:"E_OK",
    1:"E_NOK",
    0xFF:"E_NTF",
    0xFE:"E_PEN",
    0xFD:"E_ISB",
    0xEF:"E_ISD",
    0xEE:"E_UCS",
    0xED:"E_UBS",
    0xEC:"E_INV"
}

BASE_PACKET_SIZE = 8
Shall_i_SEND = False
class EtmTesterMain(QtWidgets.QMainWindow, Ui_LowerTester):
    '''Ui setup'''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setupUi(self)
        '''Logo'''
        self.setWindowIcon(QtGui.QIcon('logo.jpg'))
        '''Button connections'''
        self.Button_icmpEchoRequest.clicked.connect(ICMPV6_ECHO_REQUEST)
        self.Button_RSQ.clicked.connect(READ_SIGNAL_QUALITY)
        self.Button_RDR.clicked.connect(READ_DIAG_RESULT)
        self.Button_activateTestMode.clicked.connect(ACTIVATE_TEST_MODE)
        self.Button_setPhyMode.clicked.connect(SET_PHY_TX_MODE)
        self.Button_NDPClear.clicked.connect(NDP_CLEAR_CACHE)
        self.Button_getVersion.clicked.connect(getVersion)
        self.Button_endTest.clicked.connect(ETM_END_TEST)
        self.Button_startTest.clicked.connect(ETM_START_TEST)
        self.Button_configureSocket.clicked.connect(CONFIGURE_SOCKET_TEST)
        self.Button_shutDown.clicked.connect(SHUT_DOWN_TEST)
        self.Button_tcpConnect.clicked.connect(TCP_CONNECT_TEST)
        self.Button_listenAccept.clicked.connect(LISTEN_AND_ACCEPT)
        self.Button_createAndBind.clicked.connect(lambda :_CREATE_AND_BIND(self.crAndBindLocalIpAddr.text(),self.CrAndBindLocalPort.text(),self.crAndBind_doBind.isChecked()))
        self.Button_connect.clicked.connect(self.connectIP)
        self.Button_sendData.clicked.connect(lambda : Send_Data(self.sendDataSocId.text(),self.sendDataDestIP.text(),self.sendDataPort.text(),self.sendDataData.text()))
        self.Button_closeSocket.clicked.connect(lambda :Close_Socket(self.closeSocketID.text(),self.doAbort.isChecked()))
        self.Button_recvAndFwd.clicked.connect(lambda :rcvFwd(self.rcvFwdSocketId.text(),self.rcvFwdMaxFwd.text(),self.rcvFwdMaxLen.text()))
        self.crAndBindConnection.clicked.connect(lambda : self.setConnection(self.crAndBindConnection))
        self.configureSocketGID.clicked.connect(lambda: self.setConnection(self.configureSocketGID))
        self.shutDownGID.clicked.connect(lambda: self.setConnection(self.shutDownGID))
        self.actionSave_Console_logs.triggered.connect(saveConsoleLogs)
        self.sendData_udp.setChecked(True) # default value
        self.label_tcpflag.hide()
        self.CBox_sendData_tcp_flag.hide()

        self.actionSave_Console_logs.setShortcut("Ctrl+s")

        self.actionClear_Console.setShortcut("ctrl+x")
        self.actionClear_Console.triggered.connect(lambda : self.console.clear())

        self.actionHide_Console.setShortcut("ctrl+h")
        self.actionHide_Console.triggered.connect(lambda : self.console.hide())

        self.actionShow_Console.setShortcut("ctrl+j")
        self.actionHide_Console.triggered.connect(lambda: self.console.show())

        '''Menu'''
        self.actionAdd_TestCase_Seq.triggered.connect(getTestCases)

    def setConnection(self,checkBox):
        if checkBox.isChecked() ==True:
            checkBox.setText("UDP")
        else:
            checkBox.setText("TCP")

    '''Local definitions'''
    def connectIP(self):
        self.EtmServiceTab.setEnabled(True)
        try:
            ipaddress.ip_address(self.etmIpAddr.text())
        except:
            LOG_ERROR("Invalid Etm IP Address")
            return
        try:
            ipaddress.ip_address(self.myIP.text())
        except:
            LOG_ERROR("Invalid myIP IP Address")
            return
        self.upperTesterIP = self.etmIpAddr.text()
        self.myIPaddr = self.myIP.text()
        self.EtmPort = self.portNum.text()
        self.interface = self.Cbox_EthAdopter.currentText()
        self.Button_createAndBind.setEnabled(True)
        self.Button_startTest.setEnabled(True)
        self.Button_endTest.setEnabled(True)
        self.Button_getVersion.setEnabled(True)
        self.Button_closeSocket.setEnabled(True)
        self.Button_recvAndFwd.setEnabled(True)
        self.Button_sendData.setEnabled(True)
        self.crAndBindLocalIpAddr.setEnabled(True)
        self.CrAndBindLocalPort.setEnabled(True)
        self.console.setTextColor(QColor(84,255,255))
        self.console.append("Upper Tester IPaddress         {}".format(self.upperTesterIP))
        self.console.append("My IPaddress                   {}".format(self.myIPaddr))
        self.console.append("Upper Tester Port num          {}".format(self.EtmPort))
        self.console.append("Interface                      {}".format(self.Cbox_EthAdopter.currentText()))

    def rawDataParse(self,packetResponse):
        if packetResponse.PID == GET_VERSION and packetResponse.GID == GENERAL:
            OUT = "Result : {}   Version {}.{}".format(RESULT[packetResponse.RID],packetResponse.MajorVer,packetResponse.MinorVer)
            self.versionGetResult.setText(OUT)
        if packetResponse.PID == END_TEST and packetResponse.GID == GENERAL:
            OUT = "Result : {}".format(RESULT[packetResponse.RID])
            # self.endTestResult.setText(OUT)
        if packetResponse.PID == START_TEST and packetResponse.GID == GENERAL:
            OUT = "Result : {}".format(RESULT[packetResponse.RID])
            # self.startTestResult.setText(OUT)
        if packetResponse.PID == CLOSE_SOCKET:
            OUT = "Result : {}".format(RESULT[packetResponse.RID])
            self.closeSocketResult.setText(OUT)
        if packetResponse.PID == CREATE_AND_BIND and (packetResponse.GID == _UDP or packetResponse.GID == TCP):
            OUT = "Result : {} SocketId : {}".format(RESULT[packetResponse.RID], packetResponse.SocketId)
            if(packetResponse.RID == 0x0):
                self.rcvFwdSocketId.setText(str(packetResponse.SocketId))
            self.createBindResult.setText(OUT)
        if packetResponse.PID == SEND_DATA and packetResponse.GID == _UDP:
            OUT = "Result : {}".format(RESULT[packetResponse.RID])
            self.sendDataResult.setText(OUT)
        if packetResponse.PID == 0xff and packetResponse.GID == NDP:
            OUT = "Result : {}".format(RESULT[packetResponse.RID])
            self.sendDataResult.setText(OUT)
        if packetResponse.PID == RECEIVE_AND_FORWARD and packetResponse.GID == _UDP:
            OUT = "Result : {} Drop Count : {}".format(RESULT[packetResponse.RID],packetResponse.dropCnt)
            self.rcvFwdResult.setText(OUT)
        if packetResponse.PID == _READ_SIGNAL_QUALITY and packetResponse.GID == PHY:
            if packetResponse.RID != 0:
                self.RSQ_result.setText("Result E_IFF")
            else:
                self.RSQ_result.setText("{}%".format(packetResponse.sigQuality))
        if packetResponse.PID == _READ_DIAG_RESULT and packetResponse.GID == PHY:
            if packetResponse.RID != 0:
                self.RDR_result.setText("Result E_IFF")
            else:
                self.RDR_result.setText(PhyDiagResult[packetResponse.diagResult])
        if packetResponse.PID == _ACTIVATE_TEST_MODE and packetResponse.GID == PHY:
            if packetResponse.RID != 0:
                self.activateTestmodeResult.setText("Result E_IFF")
            else:
                self.activateTestmodeResult.setText("Result {}".format(RESULT[packetResponse.RID]))
        if packetResponse.PID == _SET_PHY_TX_MODE and packetResponse.GID == PHY:
            if packetResponse.RID != 0:
                self.setPHYModeResult.setText("Result E_IFF")
            else:
                self.setPHYModeResult.setText("Result {}".format(RESULT[packetResponse.RID]))
        pass

    def closeEvent(self, a0: QtGui.QCloseEvent) :
        global RUN
        RUN = False
        print("UI closed")

    '''Public Members'''
    upperTesterIP = "fd53:7cb8:383:e::73"
    myIPaddr = "fd53:7cb8:0383:000e::3aa"
    interface = "Ethernet 4"
    EtmPort = 50444
    showRawOutput = None

Etm_CreateBindData = None
EtmData = None

# Send Data TCF Flag
sendData_flag = {"PSH":0x08,"URG":0x20,"PSH+URG":0x28}
tcp_PSH = 0x08
tcp_URG = 0x20
tcp_PSHnURG = 0x28

# Standerd Results
E_OK  = 0x00  # The service primitive has performed successfully
E_NOK = 0x01  # General error (same as E_NOT_OK)

# Testability Specific
E_NTF = 0xFF  # The requested service primitive was not found
E_PEN = 0xFE  # The Upper Tester or a service primitive is pending
E_ISB = 0xFD  # Insufficient buffer size

# Service Primitive Specific
E_ISD = 0xEF  # Invalid socket ID
E_UCS = 0xEE  # Unable to create socket or no free socket
E_UBS = 0xED  # Unable to bind socket, port taken
E_INV = 0xEC  # Invalid Input or Parameter

'''
Service primitives are grouped in service groups. While service primitives define the functionality, a service group
defines the functional context. The Group Identifier is represented by the 7-Bit GID field in the protocol header.
'''
#GroupName  GIDs
GENERAL =   0x00
_UDP     =   0x01
TCP     =   0x02
ICMP    =   0x03
ICMPv6  =   0x04
_IP      =   0x05
_IPv6    =   0x06
DHCP    =   0x07
DHCPv6  =   0x08
ARP     =   0x09
NDP     =   0x0A
PHY     =   0x0C

# Service Primitives  PID
''' 
The Service Primitive Identifier is represented by the 8-Bit PID field in the protocol header. Depending on a service 
group a service primitive (SP) may have a different set of parameters. The separation between the different parameter 
sets for each group is done by creation of separate and atomic service primitives using the same service identifier 
(PID) but a different GID and set of parameters.The following table gives an overview on the service primitives 
supported by this specification and corresponding service groups:
'''
#SP name                PID     Gen     UDP     TCP
GET_VERSION =           0x01    #m
START_TEST =            0x02    #m
END_TEST =              0x03    #m
CLOSE_SOCKET =          0x00            #m      m
CREATE_AND_BIND  =      0x01            #m      m
SEND_DATA =             0x02            #m      m
RECEIVE_AND_FORWARD =   0x03            #m      m
LISTEN_AND_ACCEPT =     0x04#                   m
CONNECT =               0x05#                   m
CONFIGURE_SOCKET =      0x06            #m      m
SHUTDOWN =              0x07            #e      e

#Service Primitives PID Type
_READ_SIGNAL_QUALITY  =  0x00 #mandatory
_READ_DIAG_RESULT     =  0x01 #mandatory
_ACTIVATE_TEST_MODE   =  0x02 #mandatory
_SET_PHY_TX_MODE      =  0x03 #mandatory

#ICMPV6
ECHO_REQUEST = 0x00 #e
#(m= mandatory, o = optional, e = extension)

# Result of the cable diagnostics:
PhyDiagResult = ["Cable diagnostic ok","Cable diagnostic failed","Short circuit detected","Open circuit detected"]

def ICMPV6_ECHO_REQUEST():
    global widget, DataPacket, packetResponse, Shall_i_SEND
    widget.icmp_result.setText("Result ##")
    LOG("-----ICMPV6 Echo Request-------")
    try:
        addr = ipaddress.ip_address(widget.icmp_destip.text())
    except:
        LOG_ERROR("Invalid IPv6 Address")
        return
    widget.icmpResponse_console.clear()

    IPlist = addr.exploded
    IPlist = IPlist.split(':')
    IPaddrString = ' '.join([str(elem) for elem in IPlist])
    IPaddrString = '0010' + IPaddrString
    IPinBytes = bytes.fromhex(IPaddrString)

    Etm_ICMPEcho = EtmPackets.Etm_ICMPEchoRequest()
    Etm_ICMPEcho.GID = ICMPv6
    Etm_ICMPEcho.PID = ECHO_REQUEST
    Etm_ICMPEcho.if_name = widget.icmp_ifname.text()
    Etm_ICMPEcho.Length = BASE_PACKET_SIZE + 3 + 18+ stringSize(widget.icmp_ifname.text()) + stringSize(widget.icmp_data.text())
    # 3 = BOM field, + actual text size + 1 = termination field
    Etm_ICMPEcho.if_name_len = 3 +  stringSize(widget.icmp_ifname.text()) + 1
    Etm_ICMPEcho.data_size = stringSize(widget.icmp_data.text())
    Etm_ICMPEcho.data = widget.icmp_data.text()
    Etm_ICMPEcho.destAddr = IPinBytes
    LOG("::Etm Close_Socket Data to be sent....")
    LOG(Etm_ICMPEcho.show(dump=True))
    DataPacket = Etm_ICMPEcho
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

    # Trying
    BPF_filter = "icmp6[icmptype] == icmp6-echo"
    print(BPF_filter)
    t = scapy.sendrecv.AsyncSniffer(count=1, store=True, filter=BPF_filter, prn=lambda x: print_ICMP_to_ICMPv6(x),
                                    iface=widget.interface)
    t.start()
    time.sleep(2)

def print_ICMP_to_ICMPv6(x):
    widget.icmpResponse_console.append("ICMP Request Received from Target")
    widget.icmpResponse_console.append(x.show(dump=True))

def READ_SIGNAL_QUALITY():
    global widget, DataPacket, packetResponse, Shall_i_SEND
    OUT = "X%"
    widget.closeSocketResult.setText(OUT)
    LOG("-----READ_SIGNAL_QUALITY-------")
    Etm_ReadSignalQuality = EtmPackets.Etm_PHYSignalQuality()
    Etm_ReadSignalQuality.GID = PHY
    Etm_ReadSignalQuality.PID = _READ_SIGNAL_QUALITY
    Etm_ReadSignalQuality.if_name = widget.RSQ_ifName.text()
    Etm_ReadSignalQuality.Length = BASE_PACKET_SIZE + 3 +  stringSize(widget.RSQ_ifName.text())
    # 3 = BOM field, + actual text size + 1 = termination field
    Etm_ReadSignalQuality.if_name_len = 3 +  stringSize(widget.RSQ_ifName.text()) + 1
    LOG("::Etm Close_Socket Data to be sent....")
    LOG(Etm_ReadSignalQuality.show(dump=True))
    DataPacket = Etm_ReadSignalQuality
    packetResponse = EtmPackets.Etm_Resp_PHYSignalQuality
    Shall_i_SEND = True

def READ_DIAG_RESULT():
    global widget, DataPacket, packetResponse, Shall_i_SEND
    OUT = "X%"
    widget.closeSocketResult.setText(OUT)
    LOG("-----READ_DIAG RESULT-------")
    Etm_PHYDiag = EtmPackets.Etm_PHYReadDiagResult()
    Etm_PHYDiag.GID = PHY
    Etm_PHYDiag.PID = _READ_DIAG_RESULT
    Etm_PHYDiag.if_name = widget.RDR_ifName.text()
    Etm_PHYDiag.Length = BASE_PACKET_SIZE + 3 + stringSize(widget.RDR_ifName.text())
    # 3 = BOM field, + actual text size + 1 = termination field
    Etm_PHYDiag.if_name_len = 3 + stringSize(widget.RSQ_ifName.text()) + 1
    LOG("::Etm Close_Socket Data to be sent....")
    LOG(Etm_PHYDiag.show(dump=True))
    DataPacket = Etm_PHYDiag
    packetResponse = EtmPackets.Etm_Resp_PHYReadDiagResult
    Shall_i_SEND = True

def ACTIVATE_TEST_MODE():
    global widget, DataPacket, packetResponse, Shall_i_SEND
    OUT = "X%"
    widget.closeSocketResult.setText(OUT)
    LOG("-----ACTIVATE_TEST_MODE-------")
    Etm_PHYTestMode = EtmPackets.Etm_PHYActivateTestMode()
    Etm_PHYTestMode.GID = PHY
    Etm_PHYTestMode.PID = _ACTIVATE_TEST_MODE
    Etm_PHYTestMode.if_name = widget.activateTest_ifName.text()
    Etm_PHYTestMode.Length = BASE_PACKET_SIZE + 3 + stringSize(widget.activateTest_ifName.text()) + 1
    Etm_PHYTestMode.testMode = widget.CBox_activateTestMode.currentIndex()
    # 3 = BOM field, + actual text size + 1 = termination field
    Etm_PHYTestMode.if_name_len = 3 + stringSize(widget.RSQ_ifName.text()) + 1
    LOG("::Etm Close_Socket Data to be sent....")
    LOG(Etm_PHYTestMode.show(dump=True))
    DataPacket = Etm_PHYTestMode
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

def SET_PHY_TX_MODE():
    global widget, DataPacket, packetResponse, Shall_i_SEND
    OUT = "X%"
    widget.closeSocketResult.setText(OUT)
    LOG("-----ACTIVATE_TEST_MODE-------")
    Etm_PHYTxMode = EtmPackets.Etm_PHYSetTxMode()
    Etm_PHYTxMode.GID = PHY
    Etm_PHYTxMode.PID = _SET_PHY_TX_MODE
    Etm_PHYTxMode.if_name = widget.setPHYTxMode_ifName.text()
    Etm_PHYTxMode.Length = BASE_PACKET_SIZE + 3 + stringSize(widget.activateTest_ifName.text()) + 1
    Etm_PHYTxMode.txMode = widget.CBox_setPHYMode.currentIndex()
    # 3 = BOM field, + actual text size + 1 = termination field
    Etm_PHYTxMode.if_name_len = 3 + stringSize(widget.RSQ_ifName.text()) + 1
    LOG("::Etm Close_Socket Data to be sent....")
    LOG(Etm_PHYTxMode.show(dump=True))
    DataPacket = Etm_PHYTxMode
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

def NDP_CLEAR_CACHE():
    global EtmData, widget, DataPacket, packetResponse, Shall_i_SEND
    OUT = "Result : ##"
    # widget.startTestResult.setText(OUT)
    LOG('-------Start Test PID------')
    EtmData.PID = 0xff
    EtmData.GID = NDP
    EtmData.Length = 8
    LOG("::Etm ETM_START_TEST Data to be sent....")
    LOG(EtmData.show(dump=True))
    DataPacket = EtmData
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

def TCP_CONNECT_TEST():
    global EtmData, widget, DataPacket, packetResponse, Shall_i_SEND
    OUT = "Result : ##"
    LOG('-------TCP Connect Test PID------')
    # Format the Ipv6 address
    addr = ipaddress.ip_address(widget.tcpConnectDestIP.text())
    IPlist = addr.exploded
    IPlist = IPlist.split(':')
    IPaddrString = ' '.join([str(elem) for elem in IPlist])
    IPaddrString = '0010' + IPaddrString
    IPinBytes = bytes.fromhex(IPaddrString)

    Etm_CONNECT = EtmPackets.Etm_TCPConnect()
    Etm_CONNECT.PID = CONNECT
    Etm_CONNECT.GID = TCP
    Etm_CONNECT.Length = 12
    Etm_CONNECT.socketId = int(widget.tcpConnectSocketID.text())
    Etm_CONNECT.destPort = int(widget.tcpConnectDestPort.text())
    Etm_CONNECT.destAddress =IPinBytes
    LOG("::Etm TCP Connect Data to be sent....")
    LOG(Etm_CONNECT.show(dump=True))
    DataPacket = Etm_CONNECT
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

def LISTEN_AND_ACCEPT():
    global EtmData, widget, DataPacket, packetResponse, Shall_i_SEND
    OUT = "Result : ##"
    LOG('-------LISTEN AND ACCEPT Test PID------')

    Etm_ListenAccept = EtmPackets.Etm_ListenAcceptPacket()
    Etm_ListenAccept.PID = 4
    Etm_ListenAccept.GID = TCP
    Etm_ListenAccept.Length = 8 + 4
    Etm_ListenAccept.listenSocketId = int(widget.listenAcceptSocketID.text())
    Etm_ListenAccept.maxCon = int(widget.listenAcceptMaxConn.text())
    LOG("::Etm TCP Connect Data to be sent....")
    LOG(Etm_ListenAccept.show(dump=True))
    DataPacket = Etm_ListenAccept
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

def CONFIGURE_SOCKET_TEST():
    global EtmData, widget, DataPacket, packetResponse, Shall_i_SEND
    OUT = "Result : ##"
    LOG('-------CONFIGURE SOCKET Test PID------')
    if widget.configureSocketGID.isChecked() == True:
        GID_CONNECT = _UDP
    else:
        GID_CONNECT = TCP

    Etm_ConfigureSocket = EtmPackets.Etm_ConfigureSocket()
    Etm_ConfigureSocket.PID = CONFIGURE_SOCKET
    Etm_ConfigureSocket.GID = GID_CONNECT
    Etm_ConfigureSocket.Length = 12 + stringSize(widget.configureSocketParmValue.text())
    Etm_ConfigureSocket.socketId = int(widget.configureSocketSocketID.text())
    Etm_ConfigureSocket.paramId = int(widget.CBox_configureSocketParamIDs.currentIndex())
    Etm_ConfigureSocket.varDataLen = 1
    Etm_ConfigureSocket.paramVal = int(widget.configureSocketParmValue.text())

    LOG("::Etm CONFIGURE SOCKET to be sent....")
    LOG(Etm_ConfigureSocket.show(dump=True))
    DataPacket = Etm_ConfigureSocket
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

def SHUT_DOWN_TEST():
    global EtmData, widget, DataPacket, packetResponse, Shall_i_SEND
    LOG('-------Shut Down SOCKET Test PID------')
    if widget.shutDownGID.isChecked() == True:
        GID_CONNECT = _UDP
    else:
        GID_CONNECT = TCP
    Etm_ShutDownPac = EtmPackets.Etm_ShutDown()
    Etm_ShutDownPac.PID = SHUTDOWN
    Etm_ShutDownPac.GID = GID_CONNECT
    Etm_ShutDownPac.Length = 8 + 3
    Etm_ShutDownPac.socketId = int(widget.shutDownSocketID.text())
    Etm_ShutDownPac.typeid = int(widget.shutDownType.text())

    LOG("::Etm CONFIGURE SOCKET to be sent....")
    LOG(Etm_ShutDownPac.show(dump=True))
    DataPacket = Etm_ShutDownPac
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

def ETM_START_TEST():
    global EtmData ,widget,DataPacket,packetResponse,Shall_i_SEND
    OUT = "Result : ##"
    # widget.startTestResult.setText(OUT)
    LOG('-------Start Test PID------')
    EtmData.PID = START_TEST
    EtmData.GID = GENERAL
    EtmData.Length = 8
    LOG("::Etm ETM_START_TEST Data to be sent....")
    LOG(EtmData.show(dump=True))
    DataPacket = EtmData
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True


def ETM_END_TEST():
    global widget,DataPacket,packetResponse,Shall_i_SEND
    OUT = "Result : ##"
    # widget.endTestResult.setText(OUT)
    LOG('-------End Test------')
    global EtmData
    EtmData.PID = END_TEST
    EtmData.GID = GENERAL
    EtmData.Length = 8
    LOG("::Etm ETM_END_TEST Data to be sent....")
    LOG(EtmData.show(dump=True))
    # sendToIOC(EtmData,EtmPackets.Etm)
    DataPacket = EtmData
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

def getVersion():
    global widget,DataPacket,packetResponse,Shall_i_SEND
    OUT = "Result : ##   Version ##.##"
    widget.versionGetResult.setText(OUT)
    LOG ("--------Getversion-------")
    global EtmData
    EtmData.GID = GENERAL
    EtmData.PID = GET_VERSION
    EtmData.Length = 8
    LOG("::Etm GET_VERSION Data to be sent....")
    LOG(EtmData.show(dump=True))
    # sendToIOC(EtmData,EtmPackets.EtmRespVersion)
    DataPacket = EtmData
    packetResponse = EtmPackets.EtmRespVersion
    Shall_i_SEND = True


def _CREATE_AND_BIND(ip,port,bind):
    global widget,DataPacket,packetResponse,Shall_i_SEND
    LOG("-----Create and bind-------")
    OUT = "Result : ## SocketId : ##"
    widget.createBindResult.setText(OUT)
    if widget.crAndBindConnection.isChecked()==True:
        CONNECT = _UDP
    else:
        CONNECT = TCP
    global Etm_CreateBindData
    try:
        addr = ipaddress.ip_address(ip)
    except:
        LOG_ERROR("Invalid IPv6 Address")
        return
    IPlist= addr.exploded
    IPlist = IPlist.split(':')
    IPaddrString = ' '.join([str(elem) for elem in IPlist])
    IPaddrString = '0010'+IPaddrString
    IPinBytes = bytes.fromhex(IPaddrString)

    Etm_CreateBindData.GID = CONNECT
    Etm_CreateBindData.PID = CREATE_AND_BIND
    Etm_CreateBindData.localPort = int(port)
    Etm_CreateBindData.localAddr = IPinBytes
    Etm_CreateBindData.doBind = bind
    Etm_CreateBindData.Length = int((8 + (152 / 8)) + 2)
    LOG("::Etm CREATE_AND_BIND Data to be sent....")
    LOG(Etm_CreateBindData.show(dump=True))
    # sendToIOC(Etm_CreateBindData,EtmPackets.EtmRespCreateAndBind)
    DataPacket = Etm_CreateBindData
    packetResponse = EtmPackets.EtmRespCreateAndBind
    Shall_i_SEND = True

def Send_Data(socketid,dstIp,port,data):
    global widget,DataPacket,packetResponse,Shall_i_SEND
    # Clear the send data console logs #
    widget.sendDataConsole.clear()
    LOG("-----SendData-------")
    OUT = "Result : ##"
    widget.sendDataResult.setText(OUT)

    # Set GID as TCP or UDP
    # If UDP ?
    if widget.sendData_udp.isChecked() == True:
        addr = ipaddress.ip_address(dstIp)
        IPlist = addr.exploded
        IPlist = IPlist.split(':')
        IPaddrString = ' '.join([str(elem) for elem in IPlist])
        IPaddrString = '0010' + IPaddrString
        IPinBytes = bytes.fromhex(IPaddrString)

        Etm_SendData = EtmPackets.EtmReqSendData()
        Etm_SendData.GID = _UDP
        Etm_SendData.destPort = int(port)
        Etm_SendData.destAddr = IPinBytes

    # If TCP ?
    if widget.sendData_tcp.isChecked() == True:
        Etm_SendData = EtmPackets.EtmReqSendData_tcp()
        Etm_SendData.GID = TCP
        Etm_SendData.flag = sendData_flag[widget.CBox_sendData_tcp_flag.currentText()]

    Etm_SendData.PID = SEND_DATA
    Etm_SendData.socketId = int(socketid)
    Etm_SendData.totalLen = stringSize(data)
    Etm_SendData.varDataLen = stringSize(data)
    Etm_SendData.Data = data
    # Etm_SendData.Length = (8 + 2 +2+2+16+2+ stringSize(data))
    Etm_SendData.Length = (8 + 24 + stringSize(data))
    LOG("::size of sendpacket is "+str(Etm_SendData.Length))
    LOG(Etm_SendData.show(dump=True))
    # sendToIOC(Etm_SendData,EtmPackets.Etm)
    DataPacket = Etm_SendData
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True
    BPF_filter = "src host fd53:7cb8:383:e::73 && dst host {} && dst port {} ".format(dstIp,port)
    print (BPF_filter)
    t = scapy.sendrecv.AsyncSniffer(count=1,store=True,filter=BPF_filter,prn = lambda x : print_to_send_console(x),iface=widget.interface)
    t.start()
    time.sleep(2)

def print_to_send_console(x):
    widget.sendDataConsole.append("sport = {}\ndport = {}\nPayload : {}".format(x[UDP].sport,x[UDP].dport,x[Raw].load.hex()))

def Close_Socket(socketid,abort):
    global widget,DataPacket,packetResponse,Shall_i_SEND
    OUT = "Result : ##"
    widget.closeSocketResult.setText(OUT)
    LOG("-----Close Socket-------")
    Etm_CloseSocket = EtmPackets.EtmReqSocketClose()
    Etm_CloseSocket.GID = _UDP
    Etm_CloseSocket.PID = CLOSE_SOCKET
    Etm_CloseSocket.abort = abort
    Etm_CloseSocket.socketId = int(socketid)
    Etm_CloseSocket.Length = BASE_PACKET_SIZE + 2 + 1
    LOG("::Etm Close_Socket Data to be sent....")
    LOG(Etm_CloseSocket.show(dump=True))
    # sendToIOC(Etm_CloseSocket, EtmPackets.Etm)
    DataPacket = Etm_CloseSocket
    packetResponse = EtmPackets.Etm
    Shall_i_SEND = True

def rcvFwd(socketid,maxfwd,maxrcv):
    global widget,DataPacket,packetResponse,Shall_i_SEND
    LOG("-----Receive and FWD-------")
    OUT = "Result : ## Drop Count : ##"
    widget.rcvFwdResult.setText(OUT)
    Etm_RcvFwd = EtmPackets.Etm_ReceiveAndFwd()
    Etm_RcvFwd.GID = _UDP
    Etm_RcvFwd.PID = RECEIVE_AND_FORWARD
    Etm_RcvFwd.socketId = int(socketid)
    Etm_RcvFwd.maxFwd = int(maxfwd)
    Etm_RcvFwd.maxLen = int(maxrcv)
    Etm_RcvFwd.Length = BASE_PACKET_SIZE + 2 + 2
    LOG("::Etm Receive and FWD Data to be sent....")
    LOG(Etm_RcvFwd.show(dump=True))
    # sendToIOC(Etm_RcvFwd, EtmPackets.Etm_RespReceiveAndFwd)
    DataPacket = Etm_RcvFwd
    packetResponse = EtmPackets.Etm_RespReceiveAndFwd
    Shall_i_SEND = True


def getTestCases():
    LOG("Waiting for Test cases")

def saveConsoleLogs():
    global widget
    str = widget.console.toPlainText()
    name = QFileDialog.getSaveFileName(widget,'Save File')
    if name[0] is '':
        return
    file = open(name[0],'w+')
    file.write(str)
    s="File saved at : {}".format(name[0])
    LOG(s)

def stringSize(s):
    return len(s.encode('utf-8'))

def sendToIOC():
    global EtmData,widget,RUN,Shall_i_SEND
    while RUN == True:
        if Shall_i_SEND == True:
            Shall_i_SEND = False
            try:
                resp = sr1(IPv6(src=str(widget.myIPaddr), dst=str(widget.upperTesterIP)) /
                           UDP(sport=int(widget.EtmPort), dport=int(widget.EtmPort)) /
                           DataPacket, iface=str(widget.interface),
                           timeout=10)
                exit = 0
            except ValueError as e:
                LOG_ERROR(e.__str__())
                LOG_ERROR("Failed to send")
                exit = 1
            if exit is 0:
                if packetResponse != "NO":
                    if resp == None:
                        LOG_ERROR("Data sent but no response received from tester")
                        continue
                    data = resp[Raw].load
                    etmOut = packetResponse(data)
                    LOG("Response from Upper tester.....")
                    LOG_RESP(etmOut.show(dump=True))
                    widget.rawDataParse(etmOut)
                    ls(resp)
                    LOG_RESP (data.hex())

                else:
                    LOG_RESP("Basic response.")
                    data = resp[Raw].load
                    elsedata= EtmPackets.Etm(data)
                    LOG_RESP(elsedata)
        else:
            time.sleep(1)


def LOG_ERROR(s):
    global widget
    # timeStamp = str(datetime.datetime.now().time())
    widget.console.setTextColor(QColor(255,0,0))
    # widget.console.append("......................At"+timeStamp)
    widget.console.append(s)
    widget.console.setTextColor(QColor(84,255,255))
    widget.console.moveCursor(QtGui.QTextCursor.End)

def LOG(s):
    global widget
    widget.console.setTextColor(QColor(84,255,255))
    widget.console.append(s)
    widget.console.setTextColor(QColor(84,255,255))
    widget.console.moveCursor(QtGui.QTextCursor.End)

def LOG_RESP(s):
    global widget
    widget.console.setTextColor(QColor(0, 170, 0))
    widget.console.append(s)
    widget.console.setTextColor(QColor(84, 255, 255))
    widget.console.moveCursor(QtGui.QTextCursor.End)

if __name__ == '__main__':
    global widget,RUN
    t1 = threading.Thread(target=sendToIOC, name="Scapy Send thread")
    app = QtWidgets.QApplication([])
    # app.setStyle('Fusion')
    # app.setStyleSheet(qdarkstyle.load_stylesheet())
    # app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    widget = EtmTesterMain()
    EtmData = EtmPackets.Etm()
    Etm_CreateBindData = EtmPackets.Etm_CreateBind()
    addrs = psutil.net_if_addrs()
    newlist = list()
    for i in addrs.keys():
        widget.Cbox_EthAdopter.addItem(i)
    widget.show()
    RUN = True # start the thread
    t1.start()
    app.exec()
    RUN = False
    t1.join()
