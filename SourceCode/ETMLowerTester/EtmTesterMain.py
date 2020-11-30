import ipaddress

#import qdarkstyle
import qdarkstyle
from PyQt5.QtWidgets import QFileDialog
from scapy.all import *
import psutil
import ctypes
import sys
import time
import datetime
# Creating Test Packet for ETM
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from PyQt5.QtGui import QDoubleValidator, QColor
from PyQt5 import QtCore, QtGui, QtWidgets
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

class EtmTesterMain(QtWidgets.QMainWindow, Ui_LowerTester):
    '''Ui setup'''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setupUi(self)
        '''Logo'''
        self.setWindowIcon(QtGui.QIcon('logo.jpg'))
        '''Button connections'''
        self.Button_getVersion.clicked.connect(getVersion)
        self.Button_endTest.clicked.connect(ETM_END_TEST)
        self.Button_startTest.clicked.connect(ETM_START_TEST)
        self.Button_createAndBind.clicked.connect(lambda :_CREATE_AND_BIND(self.crAndBindLocalIpAddr.text(),self.CrAndBindLocalPort.text(),self.crAndBind_doBind.isChecked()))
        self.Button_connect.clicked.connect(self.connectIP)
        self.Button_sendData.clicked.connect(lambda : Send_Data(self.sendDataSocId.text(),self.sendDataDestIP.text(),self.sendDataPort.text(),self.sendDataData.text()))
        self.Button_closeSocket.clicked.connect(lambda :Close_Socket(self.closeSocketID.text(),self.doAbort.isChecked()))
        self.Button_recvAndFwd.clicked.connect(lambda :rcvFwd(self.rcvFwdSocketId.text(),self.rcvFwdMaxFwd.text(),self.rcvFwdMaxLen.text()))
        self.rcvFwdSendDummy.clicked.connect(lambda:dummySend(self.CrAndBindLocalPort.text(),self.crAndBindLocalIpAddr.text()))
        self.crAndBindConnection.clicked.connect(self.setConnection)
        self.actionSave_Console_logs.triggered.connect(saveConsoleLogs)
        self.actionSave_Console_logs.setShortcut("Ctrl+s")
        self.actionClear_Console.setShortcut("ctrl+x")
        self.actionHide_Console.setShortcut("ctrl+h")
        self.actionShow_Console.setShortcut("ctrl+j")

        '''Menu'''
        self.actionAdd_TestCase_Seq.triggered.connect(getTestCases)

    def setConnection(self):
        if self.crAndBindConnection.isChecked() ==True:
            self.crAndBindConnection.setText("UDP")
        else:
            self.crAndBindConnection.setText("TCP")

    '''Local definitions'''
    def connectIP(self):
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
        self.console.setTextColor(QColor(84,255,255))
        self.console.append("Upper Tester IPaddress  " + self.upperTesterIP)
        self.console.append("My IPaddress            " + self.myIPaddr)
        self.console.append("Upper Tester Port num   " + self.EtmPort)
        self.console.append("Interface               " + self.Cbox_EthAdopter.currentText())

    def rawDataParse(self,packetResponse):
        if packetResponse.PID == GET_VERSION and packetResponse.GID == GENERAL:
            OUT = "Result : {}   Version {}.{}".format(RESULT[packetResponse.RID],packetResponse.MajorVer,packetResponse.MinorVer)
            self.versionGetResult.setText(OUT)
        if packetResponse.PID == END_TEST and packetResponse.GID == GENERAL:
            OUT = "Result : {}".format(RESULT[packetResponse.RID])
            self.endTestResult.setText(OUT)
        if packetResponse.PID == START_TEST and packetResponse.GID == GENERAL:
            OUT = "Result : {}".format(RESULT[packetResponse.RID])
            self.startTestResult.setText(OUT)
        if packetResponse.PID == CLOSE_SOCKET:
            OUT = "Result : {}".format(RESULT[packetResponse.RID])
            self.closeSocketResult.setText(OUT)
        if packetResponse.PID == CREATE_AND_BIND and packetResponse.GID == _UDP:
            OUT = "Result : {} SocketId : {}".format(RESULT[packetResponse.RID], packetResponse.SocketId)
            if(packetResponse.RID == 0x0):
                self.rcvFwdSocketId.setText(str(packetResponse.SocketId))
            self.createBindResult.setText(OUT)
        if packetResponse.PID == SEND_DATA and packetResponse.GID == _UDP:
            OUT = "Result : {}".format(RESULT[packetResponse.RID])
            self.sendDataResult.setText(OUT)
        if packetResponse.PID == RECEIVE_AND_FORWARD and packetResponse.GID == _UDP:
            OUT = "Result : {} Drop Count : {}".format(RESULT[packetResponse.RID],packetResponse.dropCnt)
            self.rcvFwdResult.setText(OUT)
            self.rcvFwdSendDummy.setEnabled(True)
        pass

    '''Public Members'''
    upperTesterIP = "fd53:7cb8:383:e::73"
    myIPaddr = "fd53:7cb8:0383:000e:0000:0000:0000:3aa"
    interface = "Ethernet 4"
    EtmPort = 6001
    showRawOutput = None

Etm_CreateBindData = None
EtmData = None

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
#(m= mandatory, o = optional, e = extension)


def ETM_START_TEST():
    global EtmData ,widget
    LOG('-------Start Test PID------')
    EtmData.PID = START_TEST
    EtmData.GID = GENERAL
    EtmData.Length = 8
    LOG("::Etm ETM_START_TEST Data to be sent....")
    LOG(EtmData.show(dump=True))
    sendToIOC(EtmData,EtmPackets.Etm)


def ETM_END_TEST():
    global widget
    LOG('-------End Test------')
    global EtmData
    EtmData.PID = END_TEST
    EtmData.GID = GENERAL
    EtmData.Length = 8
    LOG("::Etm ETM_END_TEST Data to be sent....")
    LOG(EtmData.show(dump=True))
    sendToIOC(EtmData,EtmPackets.Etm)


def getVersion():
    global widget
    LOG ("--------Getversion-------")
    global EtmData
    EtmData.GID = GENERAL
    EtmData.PID = GET_VERSION
    EtmData.Length = 8
    LOG("::Etm GET_VERSION Data to be sent....")
    LOG(EtmData.show(dump=True))
    sendToIOC(EtmData,EtmPackets.EtmRespVersion)



def _CREATE_AND_BIND(ip,port,bind):
    global widget
    LOG("-----Create and bind-------")
    if widget.crAndBindConnection.isChecked()==True:
        CONNECT = _UDP
    else:
        CONNECT = TCP
    global Etm_CreateBindData
    addr = ipaddress.ip_address(ip)
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
    sendToIOC(Etm_CreateBindData,EtmPackets.EtmRespCreateAndBind)

def Send_Data(socketid,dstIp,port,data):
    global widget
    LOG("-----SendData-------")
    addr = ipaddress.ip_address(dstIp)
    IPlist = addr.exploded
    IPlist = IPlist.split(':')
    IPaddrString = ' '.join([str(elem) for elem in IPlist])
    IPaddrString = '0010' + IPaddrString
    IPinBytes = bytes.fromhex(IPaddrString)

    Etm_SendData = EtmPackets.EtmReqSendData()
    Etm_SendData.GID = _UDP
    Etm_SendData.PID = SEND_DATA
    Etm_SendData.socketId = int(socketid)
    Etm_SendData.totalLen = stringSize(data)
    Etm_SendData.destPort = int(port)
    Etm_SendData.destAddr = IPinBytes
    Etm_SendData.Data = data
    Etm_SendData.Length = (8 + 2 +2+2+16+2+ stringSize(data))
    LOG("::size of sendpacket is "+str(Etm_SendData.Length))
    LOG(Etm_SendData.show(dump=True))
    sendToIOC(Etm_SendData,EtmPackets.Etm)

def Close_Socket(socketid,abort):
    global widget
    LOG("-----Close Socket-------")
    Etm_CloseSocket = EtmPackets.EtmReqSocketClose()
    Etm_CloseSocket.GID = _UDP
    Etm_CloseSocket.PID = CLOSE_SOCKET
    Etm_CloseSocket.abort = abort
    Etm_CloseSocket.socketId = int(socketid)
    Etm_CloseSocket.Length = BASE_PACKET_SIZE + 2 + 1
    LOG("::Etm Close_Socket Data to be sent....")
    LOG(Etm_CloseSocket.show(dump=True))
    sendToIOC(Etm_CloseSocket, EtmPackets.Etm)

def rcvFwd(socketid,maxfwd,maxrcv):
    global widget
    LOG("-----Receive and FWD-------")
    Etm_RcvFwd = EtmPackets.Etm_ReceiveAndFwd()
    Etm_RcvFwd.GID = _UDP
    Etm_RcvFwd.PID = RECEIVE_AND_FORWARD
    Etm_RcvFwd.socketId = int(socketid)
    Etm_RcvFwd.maxFwd = int(maxfwd)
    Etm_RcvFwd.maxLen = int(maxrcv)
    Etm_RcvFwd.Length = BASE_PACKET_SIZE + 2 + 2
    LOG("::Etm Receive and FWD Data to be sent....")
    LOG(Etm_RcvFwd.show(dump=True))
    sendToIOC(Etm_RcvFwd, EtmPackets.Etm_RespReceiveAndFwd)

def dummySend(port,address):
    global EtmData, widget
    port = int(port)
    resp = sr1(IPv6(src=str(widget.myIPaddr), dst=str(address)) / UDP(sport=int(widget.EtmPort), dport=port) / "ABCD1234", iface=str(widget.interface),
               timeout=15)
    if resp is None:
        return
    data = resp[Raw].load
    etmOut = EtmPackets.Etm_RespEventReceiveAndFwd(data)
    LOG_RESP(etmOut.show(dump=True))
    widget.rcvFwdAddr.setText("Address : "+ipaddress.IPv6Address(etmOut.srcAddr)._explode_shorthand_ip_string())
    widget.rcvFwdSourcePort.setText("SourcePort :"+str(etmOut.srcPort))
    widget.rcvFwdTotalLength.setText("Length : "+str(etmOut.fullLen))
    widget.rcvFwdpayload.setText(str(etmOut.payload))

def getTestCases():
    LOG("Waiting for Testcases")

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

def sendToIOC(DataPacket,packetResponse):
    global EtmData,widget
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
                return
            data = resp[Raw].load
            etmOut = packetResponse(data)
            LOG("Response from Upper tester.....")
            LOG_RESP(etmOut.show(dump=True))
            widget.rawDataParse(etmOut)
        else:
            LOG_RESP("Basic response.")
            data = resp[Raw].load
            elsedata= EtmPackets.Etm(data)
            LOG_RESP(elsedata)

def LOG_ERROR(s):
    global widget
    # timeStamp = str(datetime.datetime.now().time())
    # widget.console.setTextColor(QColor(255,0,0))
    # widget.console.append("......................At"+timeStamp)
    widget.console.append(s)
    widget.console.setTextColor(QColor(84,255,255))

def LOG(s):
    global widget
    widget.console.setTextColor(QColor(84,255,255))
    widget.console.append(s)
    widget.console.setTextColor(QColor(84,255,255))

def LOG_RESP(s):
    global widget
    widget.console.setTextColor(QColor(0, 170, 0))
    widget.console.append(s)
    widget.console.setTextColor(QColor(84, 255, 255))

if __name__ == '__main__':
    global widget
    app = QtWidgets.QApplication([])
    # app.setStyle('Fusion')
    app.setStyleSheet(qdarkstyle.load_stylesheet())
    # app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    widget = EtmTesterMain()
    EtmData = EtmPackets.Etm()
    Etm_CreateBindData = EtmPackets.Etm_CreateBind()
    addrs = psutil.net_if_addrs()
    newlist = list()
    for i in addrs.keys():
        widget.Cbox_EthAdopter.addItem(i)
    widget.show()
    app.exec()
