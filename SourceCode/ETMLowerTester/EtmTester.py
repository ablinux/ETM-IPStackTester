# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'EtmTester.ui'
#
# Created by: PyQt5 UI code generator 5.15.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_LowerTester(object):
    def setupUi(self, LowerTester):
        LowerTester.setObjectName("LowerTester")
        LowerTester.setEnabled(True)
        LowerTester.resize(941, 906)
        self.centralwidget = QtWidgets.QWidget(LowerTester)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.Button_connect = QtWidgets.QPushButton(self.centralwidget)
        self.Button_connect.setObjectName("Button_connect")
        self.gridLayout_2.addWidget(self.Button_connect, 1, 0, 1, 3)
        self.ServiceGroup = QtWidgets.QGridLayout()
        self.ServiceGroup.setObjectName("ServiceGroup")
        self.rcvFwdTotalLength = QtWidgets.QLabel(self.centralwidget)
        self.rcvFwdTotalLength.setObjectName("rcvFwdTotalLength")
        self.ServiceGroup.addWidget(self.rcvFwdTotalLength, 35, 2, 1, 1)
        self.rcvFwdMaxFwd = QtWidgets.QLineEdit(self.centralwidget)
        self.rcvFwdMaxFwd.setObjectName("rcvFwdMaxFwd")
        self.ServiceGroup.addWidget(self.rcvFwdMaxFwd, 30, 2, 1, 1)
        self.label_15 = QtWidgets.QLabel(self.centralwidget)
        self.label_15.setObjectName("label_15")
        self.ServiceGroup.addWidget(self.label_15, 30, 1, 1, 1)
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setEnabled(True)
        self.label_7.setObjectName("label_7")
        self.ServiceGroup.addWidget(self.label_7, 10, 1, 1, 1)
        self.label_14 = QtWidgets.QLabel(self.centralwidget)
        self.label_14.setObjectName("label_14")
        self.ServiceGroup.addWidget(self.label_14, 29, 1, 1, 1)
        self.rcvFwdSocketId = QtWidgets.QLineEdit(self.centralwidget)
        self.rcvFwdSocketId.setObjectName("rcvFwdSocketId")
        self.ServiceGroup.addWidget(self.rcvFwdSocketId, 29, 2, 1, 1)
        self.Button_startTest = QtWidgets.QPushButton(self.centralwidget)
        self.Button_startTest.setEnabled(False)
        self.Button_startTest.setObjectName("Button_startTest")
        self.ServiceGroup.addWidget(self.Button_startTest, 3, 0, 1, 1)
        self.line_4 = QtWidgets.QFrame(self.centralwidget)
        self.line_4.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_4.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_4.setObjectName("line_4")
        self.ServiceGroup.addWidget(self.line_4, 14, 0, 1, 5)
        self.rcvFwdResult = QtWidgets.QLabel(self.centralwidget)
        self.rcvFwdResult.setObjectName("rcvFwdResult")
        self.ServiceGroup.addWidget(self.rcvFwdResult, 34, 2, 1, 1)
        self.closeSocketResult = QtWidgets.QLabel(self.centralwidget)
        self.closeSocketResult.setEnabled(True)
        self.closeSocketResult.setObjectName("closeSocketResult")
        self.ServiceGroup.addWidget(self.closeSocketResult, 20, 2, 1, 1)
        self.label_17 = QtWidgets.QLabel(self.centralwidget)
        self.label_17.setObjectName("label_17")
        self.ServiceGroup.addWidget(self.label_17, 33, 1, 1, 1)
        self.closeSocketID = QtWidgets.QLineEdit(self.centralwidget)
        self.closeSocketID.setInputMethodHints(QtCore.Qt.ImhDigitsOnly|QtCore.Qt.ImhPreferNumbers)
        self.closeSocketID.setObjectName("closeSocketID")
        self.ServiceGroup.addWidget(self.closeSocketID, 18, 2, 1, 1)
        self.rcvFwdMaxLen = QtWidgets.QLineEdit(self.centralwidget)
        self.rcvFwdMaxLen.setObjectName("rcvFwdMaxLen")
        self.ServiceGroup.addWidget(self.rcvFwdMaxLen, 31, 2, 1, 1)
        self.label_16 = QtWidgets.QLabel(self.centralwidget)
        self.label_16.setObjectName("label_16")
        self.ServiceGroup.addWidget(self.label_16, 31, 1, 1, 1)
        self.line_5 = QtWidgets.QFrame(self.centralwidget)
        self.line_5.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_5.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_5.setObjectName("line_5")
        self.ServiceGroup.addWidget(self.line_5, 41, 0, 1, 5)
        self.label_9 = QtWidgets.QLabel(self.centralwidget)
        self.label_9.setObjectName("label_9")
        self.ServiceGroup.addWidget(self.label_9, 24, 1, 1, 1)
        self.doAbort = QtWidgets.QRadioButton(self.centralwidget)
        self.doAbort.setText("")
        self.doAbort.setObjectName("doAbort")
        self.ServiceGroup.addWidget(self.doAbort, 19, 2, 1, 1)
        self.label_13 = QtWidgets.QLabel(self.centralwidget)
        self.label_13.setObjectName("label_13")
        self.ServiceGroup.addWidget(self.label_13, 19, 1, 1, 1)
        self.sendDataPort = QtWidgets.QLineEdit(self.centralwidget)
        self.sendDataPort.setObjectName("sendDataPort")
        self.ServiceGroup.addWidget(self.sendDataPort, 24, 2, 1, 1)
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setEnabled(True)
        self.label_4.setObjectName("label_4")
        self.ServiceGroup.addWidget(self.label_4, 9, 1, 1, 1)
        self.Button_createAndBind = QtWidgets.QPushButton(self.centralwidget)
        self.Button_createAndBind.setEnabled(False)
        self.Button_createAndBind.setObjectName("Button_createAndBind")
        self.ServiceGroup.addWidget(self.Button_createAndBind, 7, 0, 1, 1)
        self.label_11 = QtWidgets.QLabel(self.centralwidget)
        self.label_11.setObjectName("label_11")
        self.ServiceGroup.addWidget(self.label_11, 26, 1, 1, 1)
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setEnabled(True)
        self.label_3.setObjectName("label_3")
        self.ServiceGroup.addWidget(self.label_3, 8, 1, 1, 1)
        self.crAndBindLocalIpAddr = QtWidgets.QLineEdit(self.centralwidget)
        self.crAndBindLocalIpAddr.setEnabled(True)
        self.crAndBindLocalIpAddr.setObjectName("crAndBindLocalIpAddr")
        self.ServiceGroup.addWidget(self.crAndBindLocalIpAddr, 8, 2, 1, 1)
        self.rcvFwdAddr = QtWidgets.QLabel(self.centralwidget)
        self.rcvFwdAddr.setObjectName("rcvFwdAddr")
        self.ServiceGroup.addWidget(self.rcvFwdAddr, 37, 2, 1, 1)
        self.line_3 = QtWidgets.QFrame(self.centralwidget)
        self.line_3.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_3.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_3.setObjectName("line_3")
        self.ServiceGroup.addWidget(self.line_3, 6, 0, 1, 5)
        self.label_18 = QtWidgets.QLabel(self.centralwidget)
        self.label_18.setObjectName("label_18")
        self.ServiceGroup.addWidget(self.label_18, 11, 1, 1, 1)
        self.crAndBindConnection = QtWidgets.QCheckBox(self.centralwidget)
        self.crAndBindConnection.setObjectName("crAndBindConnection")
        self.ServiceGroup.addWidget(self.crAndBindConnection, 11, 2, 1, 1)
        self.createBindResult = QtWidgets.QLabel(self.centralwidget)
        self.createBindResult.setEnabled(True)
        self.createBindResult.setObjectName("createBindResult")
        self.ServiceGroup.addWidget(self.createBindResult, 12, 2, 1, 1)
        self.Button_closeSocket = QtWidgets.QPushButton(self.centralwidget)
        self.Button_closeSocket.setEnabled(False)
        self.Button_closeSocket.setObjectName("Button_closeSocket")
        self.ServiceGroup.addWidget(self.Button_closeSocket, 17, 0, 1, 1)
        self.label_12 = QtWidgets.QLabel(self.centralwidget)
        self.label_12.setObjectName("label_12")
        self.ServiceGroup.addWidget(self.label_12, 18, 1, 1, 1)
        self.Button_endTest = QtWidgets.QPushButton(self.centralwidget)
        self.Button_endTest.setEnabled(False)
        self.Button_endTest.setObjectName("Button_endTest")
        self.ServiceGroup.addWidget(self.Button_endTest, 4, 0, 1, 1)
        self.endTestResult = QtWidgets.QLabel(self.centralwidget)
        self.endTestResult.setEnabled(True)
        self.endTestResult.setObjectName("endTestResult")
        self.ServiceGroup.addWidget(self.endTestResult, 4, 2, 1, 1)
        self.dummyTestPayload = QtWidgets.QLineEdit(self.centralwidget)
        self.dummyTestPayload.setObjectName("dummyTestPayload")
        self.ServiceGroup.addWidget(self.dummyTestPayload, 33, 2, 1, 1)
        self.Button_sendData = QtWidgets.QPushButton(self.centralwidget)
        self.Button_sendData.setEnabled(False)
        self.Button_sendData.setObjectName("Button_sendData")
        self.ServiceGroup.addWidget(self.Button_sendData, 22, 0, 1, 1)
        self.startTestResult = QtWidgets.QLabel(self.centralwidget)
        self.startTestResult.setEnabled(True)
        self.startTestResult.setObjectName("startTestResult")
        self.ServiceGroup.addWidget(self.startTestResult, 3, 2, 1, 1)
        self.label_20 = QtWidgets.QLabel(self.centralwidget)
        self.label_20.setObjectName("label_20")
        self.ServiceGroup.addWidget(self.label_20, 39, 1, 1, 1)
        self.crAndBind_doBind = QtWidgets.QCheckBox(self.centralwidget)
        self.crAndBind_doBind.setText("")
        self.crAndBind_doBind.setObjectName("crAndBind_doBind")
        self.ServiceGroup.addWidget(self.crAndBind_doBind, 10, 2, 1, 1)
        self.label_10 = QtWidgets.QLabel(self.centralwidget)
        self.label_10.setObjectName("label_10")
        self.ServiceGroup.addWidget(self.label_10, 25, 1, 1, 1)
        self.Button_recvAndFwd = QtWidgets.QPushButton(self.centralwidget)
        self.Button_recvAndFwd.setEnabled(False)
        self.Button_recvAndFwd.setObjectName("Button_recvAndFwd")
        self.ServiceGroup.addWidget(self.Button_recvAndFwd, 29, 0, 1, 1)
        self.sendDataSocId = QtWidgets.QLineEdit(self.centralwidget)
        self.sendDataSocId.setObjectName("sendDataSocId")
        self.ServiceGroup.addWidget(self.sendDataSocId, 25, 2, 1, 1)
        self.sendDataResult = QtWidgets.QLabel(self.centralwidget)
        self.sendDataResult.setObjectName("sendDataResult")
        self.ServiceGroup.addWidget(self.sendDataResult, 27, 2, 1, 1)
        self.CrAndBindLocalPort = QtWidgets.QLineEdit(self.centralwidget)
        self.CrAndBindLocalPort.setEnabled(True)
        self.CrAndBindLocalPort.setObjectName("CrAndBindLocalPort")
        self.ServiceGroup.addWidget(self.CrAndBindLocalPort, 9, 2, 1, 1)
        self.line_7 = QtWidgets.QFrame(self.centralwidget)
        self.line_7.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_7.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_7.setObjectName("line_7")
        self.ServiceGroup.addWidget(self.line_7, 28, 0, 1, 5)
        self.sendDataData = QtWidgets.QLineEdit(self.centralwidget)
        self.sendDataData.setObjectName("sendDataData")
        self.ServiceGroup.addWidget(self.sendDataData, 26, 2, 1, 1)
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.ServiceGroup.addWidget(self.line, 0, 0, 1, 5)
        self.rcvFwdSendDummy = QtWidgets.QPushButton(self.centralwidget)
        self.rcvFwdSendDummy.setEnabled(False)
        self.rcvFwdSendDummy.setObjectName("rcvFwdSendDummy")
        self.ServiceGroup.addWidget(self.rcvFwdSendDummy, 32, 2, 1, 1)
        self.line_2 = QtWidgets.QFrame(self.centralwidget)
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.ServiceGroup.addWidget(self.line_2, 2, 0, 1, 5)
        self.versionGetResult = QtWidgets.QLabel(self.centralwidget)
        self.versionGetResult.setEnabled(True)
        self.versionGetResult.setObjectName("versionGetResult")
        self.ServiceGroup.addWidget(self.versionGetResult, 1, 2, 1, 1)
        self.Button_getVersion = QtWidgets.QPushButton(self.centralwidget)
        self.Button_getVersion.setEnabled(False)
        self.Button_getVersion.setObjectName("Button_getVersion")
        self.ServiceGroup.addWidget(self.Button_getVersion, 1, 0, 1, 1)
        self.sendDataDestIP = QtWidgets.QLineEdit(self.centralwidget)
        self.sendDataDestIP.setObjectName("sendDataDestIP")
        self.ServiceGroup.addWidget(self.sendDataDestIP, 23, 2, 1, 1)
        self.rcvFwdSourcePort = QtWidgets.QLabel(self.centralwidget)
        self.rcvFwdSourcePort.setObjectName("rcvFwdSourcePort")
        self.ServiceGroup.addWidget(self.rcvFwdSourcePort, 36, 2, 1, 1)
        self.label_8 = QtWidgets.QLabel(self.centralwidget)
        self.label_8.setObjectName("label_8")
        self.ServiceGroup.addWidget(self.label_8, 23, 1, 1, 1)
        self.line_6 = QtWidgets.QFrame(self.centralwidget)
        self.line_6.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_6.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_6.setObjectName("line_6")
        self.ServiceGroup.addWidget(self.line_6, 21, 0, 1, 5)
        self.rcvFwdpayload = QtWidgets.QLabel(self.centralwidget)
        self.rcvFwdpayload.setObjectName("rcvFwdpayload")
        self.ServiceGroup.addWidget(self.rcvFwdpayload, 39, 2, 2, 1)
        self.gridLayout_2.addLayout(self.ServiceGroup, 2, 0, 5, 1)
        self.ConnectGroup = QtWidgets.QGridLayout()
        self.ConnectGroup.setObjectName("ConnectGroup")
        self.ethAdopter = QtWidgets.QLineEdit(self.centralwidget)
        self.ethAdopter.setObjectName("ethAdopter")
        self.ConnectGroup.addWidget(self.ethAdopter, 1, 1, 1, 1)
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setObjectName("label_2")
        self.ConnectGroup.addWidget(self.label_2, 1, 0, 1, 1)
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setObjectName("label")
        self.ConnectGroup.addWidget(self.label, 0, 0, 1, 1)
        self.etmIpAddr = QtWidgets.QLineEdit(self.centralwidget)
        self.etmIpAddr.setObjectName("etmIpAddr")
        self.ConnectGroup.addWidget(self.etmIpAddr, 0, 1, 1, 1)
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setObjectName("label_6")
        self.ConnectGroup.addWidget(self.label_6, 1, 2, 1, 1)
        self.portNum = QtWidgets.QLineEdit(self.centralwidget)
        self.portNum.setObjectName("portNum")
        self.ConnectGroup.addWidget(self.portNum, 1, 3, 1, 1)
        self.myIP = QtWidgets.QLineEdit(self.centralwidget)
        self.myIP.setObjectName("myIP")
        self.ConnectGroup.addWidget(self.myIP, 0, 3, 1, 1)
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setObjectName("label_5")
        self.ConnectGroup.addWidget(self.label_5, 0, 2, 1, 1)
        self.gridLayout_2.addLayout(self.ConnectGroup, 0, 0, 1, 3)
        self.console = QtWidgets.QTextBrowser(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("MS UI Gothic")
        font.setPointSize(9)
        self.console.setFont(font)
        self.console.setStyleSheet("background:rgb(0, 0, 0)")
        self.console.setAcceptRichText(True)
        self.console.setObjectName("console")
        self.gridLayout_2.addWidget(self.console, 2, 2, 5, 1)
        self.Button_connect.raise_()
        self.console.raise_()
        LowerTester.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(LowerTester)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 941, 21))
        self.menubar.setObjectName("menubar")
        self.menuLoad = QtWidgets.QMenu(self.menubar)
        self.menuLoad.setObjectName("menuLoad")
        LowerTester.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(LowerTester)
        self.statusbar.setObjectName("statusbar")
        LowerTester.setStatusBar(self.statusbar)
        self.actionAdd_TestCase_Seq = QtWidgets.QAction(LowerTester)
        self.actionAdd_TestCase_Seq.setObjectName("actionAdd_TestCase_Seq")
        self.actionHide_Console = QtWidgets.QAction(LowerTester)
        self.actionHide_Console.setObjectName("actionHide_Console")
        self.actionShow_Console = QtWidgets.QAction(LowerTester)
        self.actionShow_Console.setObjectName("actionShow_Console")
        self.actionClear_Console = QtWidgets.QAction(LowerTester)
        self.actionClear_Console.setObjectName("actionClear_Console")
        self.actionSave_Console_logs = QtWidgets.QAction(LowerTester)
        self.actionSave_Console_logs.setObjectName("actionSave_Console_logs")
        self.menuLoad.addAction(self.actionAdd_TestCase_Seq)
        self.menuLoad.addAction(self.actionHide_Console)
        self.menuLoad.addAction(self.actionShow_Console)
        self.menuLoad.addAction(self.actionClear_Console)
        self.menuLoad.addAction(self.actionSave_Console_logs)
        self.menubar.addAction(self.menuLoad.menuAction())

        self.retranslateUi(LowerTester)
        self.actionHide_Console.triggered.connect(self.console.hide)
        self.actionShow_Console.triggered.connect(self.console.show)
        self.actionClear_Console.triggered.connect(self.console.clear)
        QtCore.QMetaObject.connectSlotsByName(LowerTester)
        LowerTester.setTabOrder(self.Button_connect, self.etmIpAddr)
        LowerTester.setTabOrder(self.etmIpAddr, self.ethAdopter)
        LowerTester.setTabOrder(self.ethAdopter, self.myIP)
        LowerTester.setTabOrder(self.myIP, self.portNum)
        LowerTester.setTabOrder(self.portNum, self.Button_closeSocket)
        LowerTester.setTabOrder(self.Button_closeSocket, self.doAbort)
        LowerTester.setTabOrder(self.doAbort, self.Button_sendData)
        LowerTester.setTabOrder(self.Button_sendData, self.sendDataDestIP)
        LowerTester.setTabOrder(self.sendDataDestIP, self.closeSocketID)
        LowerTester.setTabOrder(self.closeSocketID, self.Button_endTest)
        LowerTester.setTabOrder(self.Button_endTest, self.Button_startTest)
        LowerTester.setTabOrder(self.Button_startTest, self.Button_getVersion)
        LowerTester.setTabOrder(self.Button_getVersion, self.crAndBindLocalIpAddr)
        LowerTester.setTabOrder(self.crAndBindLocalIpAddr, self.CrAndBindLocalPort)
        LowerTester.setTabOrder(self.CrAndBindLocalPort, self.Button_createAndBind)
        LowerTester.setTabOrder(self.Button_createAndBind, self.sendDataSocId)
        LowerTester.setTabOrder(self.sendDataSocId, self.Button_recvAndFwd)
        LowerTester.setTabOrder(self.Button_recvAndFwd, self.sendDataData)
        LowerTester.setTabOrder(self.sendDataData, self.sendDataPort)
        LowerTester.setTabOrder(self.sendDataPort, self.rcvFwdSocketId)
        LowerTester.setTabOrder(self.rcvFwdSocketId, self.rcvFwdMaxFwd)
        LowerTester.setTabOrder(self.rcvFwdMaxFwd, self.rcvFwdMaxLen)
        LowerTester.setTabOrder(self.rcvFwdMaxLen, self.rcvFwdSendDummy)

    def retranslateUi(self, LowerTester):
        _translate = QtCore.QCoreApplication.translate
        LowerTester.setWindowTitle(_translate("LowerTester", "Etm Tester"))
        self.Button_connect.setText(_translate("LowerTester", "Connect"))
        self.rcvFwdTotalLength.setText(_translate("LowerTester", "Length:##"))
        self.rcvFwdMaxFwd.setText(_translate("LowerTester", "16"))
        self.label_15.setText(_translate("LowerTester", "Max payload len"))
        self.label_7.setText(_translate("LowerTester", "Bind?"))
        self.label_14.setText(_translate("LowerTester", "Socket ID"))
        self.rcvFwdSocketId.setText(_translate("LowerTester", "0"))
        self.Button_startTest.setText(_translate("LowerTester", "Start Test"))
        self.rcvFwdResult.setText(_translate("LowerTester", "Result :Unknown Drop Count :##"))
        self.closeSocketResult.setText(_translate("LowerTester", "Result:##"))
        self.label_17.setText(_translate("LowerTester", "Paylaod to send"))
        self.closeSocketID.setText(_translate("LowerTester", "0"))
        self.rcvFwdMaxLen.setText(_translate("LowerTester", "16"))
        self.label_16.setText(_translate("LowerTester", "Max Rec len"))
        self.label_9.setText(_translate("LowerTester", "Dest Port"))
        self.label_13.setText(_translate("LowerTester", "Abort"))
        self.sendDataPort.setText(_translate("LowerTester", "1234"))
        self.label_4.setText(_translate("LowerTester", "Local Port"))
        self.Button_createAndBind.setText(_translate("LowerTester", "Create And Bind"))
        self.label_11.setText(_translate("LowerTester", "Data"))
        self.label_3.setText(_translate("LowerTester", "IP Addr"))
        self.crAndBindLocalIpAddr.setText(_translate("LowerTester", "fd53:7cb8:383:e::73"))
        self.rcvFwdAddr.setText(_translate("LowerTester", "Address :####:####:####:####:####"))
        self.label_18.setText(_translate("LowerTester", "Connection"))
        self.crAndBindConnection.setText(_translate("LowerTester", "TCP"))
        self.createBindResult.setText(_translate("LowerTester", "Result:##  SocketId:##"))
        self.Button_closeSocket.setText(_translate("LowerTester", "Close Socket"))
        self.label_12.setText(_translate("LowerTester", "Socket ID"))
        self.Button_endTest.setText(_translate("LowerTester", "End Test"))
        self.endTestResult.setText(_translate("LowerTester", "Result:##"))
        self.dummyTestPayload.setText(_translate("LowerTester", "ABCD1234"))
        self.Button_sendData.setText(_translate("LowerTester", "Send Data"))
        self.startTestResult.setText(_translate("LowerTester", "Result:##"))
        self.label_20.setText(_translate("LowerTester", "Payload Rcvd"))
        self.label_10.setText(_translate("LowerTester", "Socket ID"))
        self.Button_recvAndFwd.setText(_translate("LowerTester", "Receive and Forward"))
        self.sendDataSocId.setText(_translate("LowerTester", "0"))
        self.sendDataResult.setToolTip(_translate("LowerTester", "<html><head/><body><p>Please note: because of the non-blocking behavior of Service Primitives a positive response does NOT signal the success of the transmission, but the success of issuing the transmission.</p></body></html>"))
        self.sendDataResult.setText(_translate("LowerTester", "Result:##"))
        self.CrAndBindLocalPort.setText(_translate("LowerTester", "1234"))
        self.sendDataData.setText(_translate("LowerTester", "ABCDEFGHI"))
        self.rcvFwdSendDummy.setToolTip(_translate("LowerTester", "<html><head/><body><p>This send a dummy data &quot;ABCD1234&quot;</p></body></html>"))
        self.rcvFwdSendDummy.setText(_translate("LowerTester", "Test"))
        self.versionGetResult.setText(_translate("LowerTester", "Result:##  Version:##.##"))
        self.Button_getVersion.setText(_translate("LowerTester", "GetVersion"))
        self.sendDataDestIP.setText(_translate("LowerTester", "fd53:7cb8:383:e::73"))
        self.rcvFwdSourcePort.setText(_translate("LowerTester", "SourcePort: ##"))
        self.label_8.setText(_translate("LowerTester", "Dest IP"))
        self.rcvFwdpayload.setText(_translate("LowerTester", "-----------------------------------------------------"))
        self.ethAdopter.setToolTip(_translate("LowerTester", "<html><head/><body><p>Ethernet Adopter name EX: Ethernet 4</p></body></html>"))
        self.ethAdopter.setText(_translate("LowerTester", "Ethernet 4"))
        self.label_2.setText(_translate("LowerTester", "Eth Adopter"))
        self.label.setText(_translate("LowerTester", "Upper tester IPV6 Address    "))
        self.etmIpAddr.setToolTip(_translate("LowerTester", "<html><head/><body><p>Add Upper Tester IP address (IPV6)</p></body></html>"))
        self.etmIpAddr.setText(_translate("LowerTester", "fd53:7cb8:383:e::73"))
        self.label_6.setText(_translate("LowerTester", "Etm Port"))
        self.portNum.setText(_translate("LowerTester", "6001"))
        self.myIP.setText(_translate("LowerTester", "fd53:7cb8:0383:000e:0000:0000:0000:3aa"))
        self.label_5.setText(_translate("LowerTester", "My IpAddress"))
        self.console.setHtml(_translate("LowerTester", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS UI Gothic\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p align=\"justify\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; color:#00ffff;\">Etm tester Beta v .1.0</span></p></body></html>"))
        self.menuLoad.setTitle(_translate("LowerTester", "Menu"))
        self.actionAdd_TestCase_Seq.setText(_translate("LowerTester", "Add TestCase Seq"))
        self.actionHide_Console.setText(_translate("LowerTester", "Hide Console"))
        self.actionShow_Console.setText(_translate("LowerTester", "Show Console"))
        self.actionClear_Console.setText(_translate("LowerTester", "Clear Console"))
        self.actionSave_Console_logs.setText(_translate("LowerTester", "Save Console logs"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    LowerTester = QtWidgets.QMainWindow()
    ui = Ui_LowerTester()
    ui.setupUi(LowerTester)
    LowerTester.show()
    sys.exit(app.exec_())