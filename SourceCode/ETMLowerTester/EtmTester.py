# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'EtmTesterConsoleWithTABS_v1_1.ui'
#
# Created by: PyQt5 UI code generator 5.15.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_LowerTester(object):
    def setupUi(self, LowerTester):
        LowerTester.setObjectName("LowerTester")
        LowerTester.resize(691, 786)
        self.centralwidget = QtWidgets.QWidget(LowerTester)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox.setObjectName("groupBox")
        self.gridLayout = QtWidgets.QGridLayout(self.groupBox)
        self.gridLayout.setObjectName("gridLayout")
        self.myIP = QtWidgets.QLineEdit(self.groupBox)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.myIP.setFont(font)
        self.myIP.setObjectName("myIP")
        self.gridLayout.addWidget(self.myIP, 0, 6, 1, 1)
        self.label = QtWidgets.QLabel(self.groupBox)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.label_2 = QtWidgets.QLabel(self.groupBox)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)
        self.portNum = QtWidgets.QLineEdit(self.groupBox)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.portNum.setFont(font)
        self.portNum.setObjectName("portNum")
        self.gridLayout.addWidget(self.portNum, 1, 6, 1, 1)
        self.label_6 = QtWidgets.QLabel(self.groupBox)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.gridLayout.addWidget(self.label_6, 1, 4, 1, 1)
        self.Button_connect = QtWidgets.QPushButton(self.groupBox)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Button_connect.sizePolicy().hasHeightForWidth())
        self.Button_connect.setSizePolicy(sizePolicy)
        self.Button_connect.setObjectName("Button_connect")
        self.gridLayout.addWidget(self.Button_connect, 0, 7, 3, 1)
        self.etmIpAddr = QtWidgets.QLineEdit(self.groupBox)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.etmIpAddr.setFont(font)
        self.etmIpAddr.setObjectName("etmIpAddr")
        self.gridLayout.addWidget(self.etmIpAddr, 0, 1, 1, 1)
        self.Cbox_EthAdopter = QtWidgets.QComboBox(self.groupBox)
        self.Cbox_EthAdopter.setObjectName("Cbox_EthAdopter")
        self.gridLayout.addWidget(self.Cbox_EthAdopter, 1, 1, 1, 1)
        self.label_5 = QtWidgets.QLabel(self.groupBox)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.gridLayout.addWidget(self.label_5, 0, 4, 1, 1)
        self.verticalLayout_3.addWidget(self.groupBox)
        self.groupBox_2 = QtWidgets.QGroupBox(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_2.sizePolicy().hasHeightForWidth())
        self.groupBox_2.setSizePolicy(sizePolicy)
        self.groupBox_2.setMinimumSize(QtCore.QSize(0, 0))
        self.groupBox_2.setObjectName("groupBox_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.groupBox_2)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.groupBox_4 = QtWidgets.QGroupBox(self.groupBox_2)
        self.groupBox_4.setTitle("")
        self.groupBox_4.setObjectName("groupBox_4")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.groupBox_4)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.Button_startTest = QtWidgets.QPushButton(self.groupBox_4)
        self.Button_startTest.setEnabled(False)
        self.Button_startTest.setObjectName("Button_startTest")
        self.horizontalLayout.addWidget(self.Button_startTest)
        spacerItem = QtWidgets.QSpacerItem(60, 20, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.Button_endTest = QtWidgets.QPushButton(self.groupBox_4)
        self.Button_endTest.setEnabled(False)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Button_endTest.sizePolicy().hasHeightForWidth())
        self.Button_endTest.setSizePolicy(sizePolicy)
        self.Button_endTest.setObjectName("Button_endTest")
        self.horizontalLayout.addWidget(self.Button_endTest)
        self.verticalLayout_2.addWidget(self.groupBox_4)
        self.EtmServiceTab = QtWidgets.QTabWidget(self.groupBox_2)
        self.EtmServiceTab.setEnabled(False)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.EtmServiceTab.sizePolicy().hasHeightForWidth())
        self.EtmServiceTab.setSizePolicy(sizePolicy)
        self.EtmServiceTab.setObjectName("EtmServiceTab")
        self.VersionGet = QtWidgets.QWidget()
        self.VersionGet.setObjectName("VersionGet")
        self.versionGetResult = QtWidgets.QLabel(self.VersionGet)
        self.versionGetResult.setEnabled(False)
        self.versionGetResult.setGeometry(QtCore.QRect(280, 60, 301, 23))
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.versionGetResult.setFont(font)
        self.versionGetResult.setObjectName("versionGetResult")
        self.Button_getVersion = QtWidgets.QPushButton(self.VersionGet)
        self.Button_getVersion.setEnabled(False)
        self.Button_getVersion.setGeometry(QtCore.QRect(10, 20, 231, 101))
        self.Button_getVersion.setObjectName("Button_getVersion")
        self.EtmServiceTab.addTab(self.VersionGet, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.crAndBindConnection = QtWidgets.QCheckBox(self.tab_2)
        self.crAndBindConnection.setGeometry(QtCore.QRect(80, 60, 222, 17))
        self.crAndBindConnection.setObjectName("crAndBindConnection")
        self.label_4 = QtWidgets.QLabel(self.tab_2)
        self.label_4.setEnabled(False)
        self.label_4.setGeometry(QtCore.QRect(320, 10, 78, 20))
        self.label_4.setObjectName("label_4")
        self.label_7 = QtWidgets.QLabel(self.tab_2)
        self.label_7.setEnabled(False)
        self.label_7.setGeometry(QtCore.QRect(10, 40, 78, 13))
        self.label_7.setObjectName("label_7")
        self.label_3 = QtWidgets.QLabel(self.tab_2)
        self.label_3.setEnabled(False)
        self.label_3.setGeometry(QtCore.QRect(10, 10, 78, 20))
        self.label_3.setObjectName("label_3")
        self.Button_createAndBind = QtWidgets.QPushButton(self.tab_2)
        self.Button_createAndBind.setEnabled(False)
        self.Button_createAndBind.setGeometry(QtCore.QRect(10, 90, 171, 31))
        self.Button_createAndBind.setObjectName("Button_createAndBind")
        self.crAndBind_doBind = QtWidgets.QCheckBox(self.tab_2)
        self.crAndBind_doBind.setGeometry(QtCore.QRect(80, 40, 222, 13))
        self.crAndBind_doBind.setText("")
        self.crAndBind_doBind.setObjectName("crAndBind_doBind")
        self.crAndBindLocalIpAddr = QtWidgets.QLineEdit(self.tab_2)
        self.crAndBindLocalIpAddr.setEnabled(False)
        self.crAndBindLocalIpAddr.setGeometry(QtCore.QRect(80, 10, 222, 20))
        self.crAndBindLocalIpAddr.setObjectName("crAndBindLocalIpAddr")
        self.createBindResult = QtWidgets.QLabel(self.tab_2)
        self.createBindResult.setEnabled(False)
        self.createBindResult.setGeometry(QtCore.QRect(300, 100, 222, 13))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.createBindResult.setFont(font)
        self.createBindResult.setObjectName("createBindResult")
        self.label_18 = QtWidgets.QLabel(self.tab_2)
        self.label_18.setGeometry(QtCore.QRect(10, 60, 78, 17))
        self.label_18.setObjectName("label_18")
        self.CrAndBindLocalPort = QtWidgets.QLineEdit(self.tab_2)
        self.CrAndBindLocalPort.setEnabled(False)
        self.CrAndBindLocalPort.setGeometry(QtCore.QRect(370, 10, 222, 20))
        self.CrAndBindLocalPort.setObjectName("CrAndBindLocalPort")
        self.EtmServiceTab.addTab(self.tab_2, "")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.label_12 = QtWidgets.QLabel(self.tab)
        self.label_12.setGeometry(QtCore.QRect(10, 10, 78, 20))
        self.label_12.setObjectName("label_12")
        self.closeSocketID = QtWidgets.QLineEdit(self.tab)
        self.closeSocketID.setGeometry(QtCore.QRect(80, 10, 111, 20))
        self.closeSocketID.setInputMethodHints(QtCore.Qt.ImhDigitsOnly|QtCore.Qt.ImhPreferNumbers)
        self.closeSocketID.setObjectName("closeSocketID")
        self.Button_closeSocket = QtWidgets.QPushButton(self.tab)
        self.Button_closeSocket.setEnabled(False)
        self.Button_closeSocket.setGeometry(QtCore.QRect(10, 70, 181, 31))
        self.Button_closeSocket.setObjectName("Button_closeSocket")
        self.closeSocketResult = QtWidgets.QLabel(self.tab)
        self.closeSocketResult.setEnabled(False)
        self.closeSocketResult.setGeometry(QtCore.QRect(260, 80, 222, 13))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.closeSocketResult.setFont(font)
        self.closeSocketResult.setObjectName("closeSocketResult")
        self.doAbort = QtWidgets.QRadioButton(self.tab)
        self.doAbort.setGeometry(QtCore.QRect(80, 40, 222, 13))
        self.doAbort.setText("")
        self.doAbort.setObjectName("doAbort")
        self.label_13 = QtWidgets.QLabel(self.tab)
        self.label_13.setGeometry(QtCore.QRect(10, 40, 78, 13))
        self.label_13.setObjectName("label_13")
        self.EtmServiceTab.addTab(self.tab, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.Button_sendData = QtWidgets.QPushButton(self.tab_3)
        self.Button_sendData.setEnabled(False)
        self.Button_sendData.setGeometry(QtCore.QRect(10, 110, 221, 31))
        self.Button_sendData.setObjectName("Button_sendData")
        self.label_11 = QtWidgets.QLabel(self.tab_3)
        self.label_11.setGeometry(QtCore.QRect(10, 70, 78, 20))
        self.label_11.setObjectName("label_11")
        self.sendDataSocId = QtWidgets.QLineEdit(self.tab_3)
        self.sendDataSocId.setGeometry(QtCore.QRect(80, 40, 222, 20))
        self.sendDataSocId.setObjectName("sendDataSocId")
        self.label_8 = QtWidgets.QLabel(self.tab_3)
        self.label_8.setGeometry(QtCore.QRect(10, 10, 78, 20))
        self.label_8.setObjectName("label_8")
        self.sendDataData = QtWidgets.QLineEdit(self.tab_3)
        self.sendDataData.setGeometry(QtCore.QRect(80, 70, 491, 20))
        self.sendDataData.setObjectName("sendDataData")
        self.sendDataResult = QtWidgets.QLabel(self.tab_3)
        self.sendDataResult.setGeometry(QtCore.QRect(340, 120, 222, 13))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.sendDataResult.setFont(font)
        self.sendDataResult.setObjectName("sendDataResult")
        self.label_9 = QtWidgets.QLabel(self.tab_3)
        self.label_9.setGeometry(QtCore.QRect(320, 10, 78, 20))
        self.label_9.setObjectName("label_9")
        self.label_10 = QtWidgets.QLabel(self.tab_3)
        self.label_10.setGeometry(QtCore.QRect(10, 40, 78, 20))
        self.label_10.setObjectName("label_10")
        self.sendDataDestIP = QtWidgets.QLineEdit(self.tab_3)
        self.sendDataDestIP.setGeometry(QtCore.QRect(80, 10, 222, 20))
        self.sendDataDestIP.setObjectName("sendDataDestIP")
        self.sendDataPort = QtWidgets.QLineEdit(self.tab_3)
        self.sendDataPort.setGeometry(QtCore.QRect(380, 10, 191, 20))
        self.sendDataPort.setObjectName("sendDataPort")
        self.EtmServiceTab.addTab(self.tab_3, "")
        self.widget = QtWidgets.QWidget()
        self.widget.setObjectName("widget")
        self.label_14 = QtWidgets.QLabel(self.widget)
        self.label_14.setGeometry(QtCore.QRect(10, 10, 78, 20))
        self.label_14.setObjectName("label_14")
        self.label_15 = QtWidgets.QLabel(self.widget)
        self.label_15.setGeometry(QtCore.QRect(10, 40, 78, 20))
        self.label_15.setObjectName("label_15")
        self.rcvFwdMaxFwd = QtWidgets.QLineEdit(self.widget)
        self.rcvFwdMaxFwd.setGeometry(QtCore.QRect(120, 40, 222, 20))
        self.rcvFwdMaxFwd.setObjectName("rcvFwdMaxFwd")
        self.rcvFwdResult = QtWidgets.QLabel(self.widget)
        self.rcvFwdResult.setGeometry(QtCore.QRect(310, 110, 291, 20))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.rcvFwdResult.setFont(font)
        self.rcvFwdResult.setObjectName("rcvFwdResult")
        self.rcvFwdSocketId = QtWidgets.QLineEdit(self.widget)
        self.rcvFwdSocketId.setGeometry(QtCore.QRect(120, 10, 222, 20))
        self.rcvFwdSocketId.setObjectName("rcvFwdSocketId")
        self.rcvFwdMaxLen = QtWidgets.QLineEdit(self.widget)
        self.rcvFwdMaxLen.setGeometry(QtCore.QRect(120, 70, 222, 20))
        self.rcvFwdMaxLen.setObjectName("rcvFwdMaxLen")
        self.Button_recvAndFwd = QtWidgets.QPushButton(self.widget)
        self.Button_recvAndFwd.setEnabled(False)
        self.Button_recvAndFwd.setGeometry(QtCore.QRect(10, 100, 231, 31))
        self.Button_recvAndFwd.setObjectName("Button_recvAndFwd")
        self.label_16 = QtWidgets.QLabel(self.widget)
        self.label_16.setGeometry(QtCore.QRect(10, 70, 78, 20))
        self.label_16.setObjectName("label_16")
        self.EtmServiceTab.addTab(self.widget, "")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setObjectName("tab_4")
        self.label_33 = QtWidgets.QLabel(self.tab_4)
        self.label_33.setGeometry(QtCore.QRect(10, 10, 78, 20))
        self.label_33.setObjectName("label_33")
        self.rcvFwdSourcePort = QtWidgets.QLabel(self.tab_4)
        self.rcvFwdSourcePort.setGeometry(QtCore.QRect(110, 62, 222, 13))
        self.rcvFwdSourcePort.setObjectName("rcvFwdSourcePort")
        self.dummyTestPayload = QtWidgets.QLineEdit(self.tab_4)
        self.dummyTestPayload.setGeometry(QtCore.QRect(110, 10, 222, 20))
        self.dummyTestPayload.setObjectName("dummyTestPayload")
        self.rcvFwdTotalLength = QtWidgets.QLabel(self.tab_4)
        self.rcvFwdTotalLength.setGeometry(QtCore.QRect(110, 43, 222, 13))
        self.rcvFwdTotalLength.setObjectName("rcvFwdTotalLength")
        self.rcvFwdAddr = QtWidgets.QLabel(self.tab_4)
        self.rcvFwdAddr.setGeometry(QtCore.QRect(110, 81, 222, 13))
        self.rcvFwdAddr.setObjectName("rcvFwdAddr")
        self.label_34 = QtWidgets.QLabel(self.tab_4)
        self.label_34.setGeometry(QtCore.QRect(16, 100, 78, 20))
        self.label_34.setObjectName("label_34")
        self.rcvFwdpayload = QtWidgets.QLabel(self.tab_4)
        self.rcvFwdpayload.setGeometry(QtCore.QRect(110, 100, 222, 20))
        self.rcvFwdpayload.setObjectName("rcvFwdpayload")
        self.rcvFwdSendDummy = QtWidgets.QPushButton(self.tab_4)
        self.rcvFwdSendDummy.setEnabled(False)
        self.rcvFwdSendDummy.setGeometry(QtCore.QRect(420, 10, 111, 121))
        self.rcvFwdSendDummy.setObjectName("rcvFwdSendDummy")
        self.EtmServiceTab.addTab(self.tab_4, "")
        self.verticalLayout_2.addWidget(self.EtmServiceTab)
        self.verticalLayout_3.addWidget(self.groupBox_2)
        self.groupBox_3 = QtWidgets.QGroupBox(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_3.sizePolicy().hasHeightForWidth())
        self.groupBox_3.setSizePolicy(sizePolicy)
        self.groupBox_3.setObjectName("groupBox_3")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.groupBox_3)
        self.verticalLayout.setObjectName("verticalLayout")
        self.console = QtWidgets.QTextBrowser(self.groupBox_3)
        font = QtGui.QFont()
        font.setFamily("MS UI Gothic")
        font.setPointSize(9)
        self.console.setFont(font)
        self.console.setStyleSheet("background:rgb(0, 0, 0)")
        self.console.setAcceptRichText(True)
        self.console.setObjectName("console")
        self.verticalLayout.addWidget(self.console)
        self.verticalLayout_3.addWidget(self.groupBox_3)
        LowerTester.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(LowerTester)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 691, 21))
        self.menubar.setObjectName("menubar")
        self.menuAdd_TestCase_Seq = QtWidgets.QMenu(self.menubar)
        self.menuAdd_TestCase_Seq.setObjectName("menuAdd_TestCase_Seq")
        LowerTester.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(LowerTester)
        self.statusbar.setObjectName("statusbar")
        LowerTester.setStatusBar(self.statusbar)
        self.actionHide_Console = QtWidgets.QAction(LowerTester)
        self.actionHide_Console.setObjectName("actionHide_Console")
        self.actionAdd_TestCase_Seq = QtWidgets.QAction(LowerTester)
        self.actionAdd_TestCase_Seq.setObjectName("actionAdd_TestCase_Seq")
        self.actionHide_Console_2 = QtWidgets.QAction(LowerTester)
        self.actionHide_Console_2.setObjectName("actionHide_Console_2")
        self.actionShow_Console = QtWidgets.QAction(LowerTester)
        self.actionShow_Console.setObjectName("actionShow_Console")
        self.actionClear_Console = QtWidgets.QAction(LowerTester)
        self.actionClear_Console.setObjectName("actionClear_Console")
        self.actionSave_Console_logs = QtWidgets.QAction(LowerTester)
        self.actionSave_Console_logs.setObjectName("actionSave_Console_logs")
        self.actionReportBug = QtWidgets.QAction(LowerTester)
        self.actionReportBug.setObjectName("actionReportBug")
        self.menuAdd_TestCase_Seq.addAction(self.actionAdd_TestCase_Seq)
        self.menuAdd_TestCase_Seq.addAction(self.actionHide_Console_2)
        self.menuAdd_TestCase_Seq.addAction(self.actionShow_Console)
        self.menuAdd_TestCase_Seq.addAction(self.actionClear_Console)
        self.menuAdd_TestCase_Seq.addAction(self.actionSave_Console_logs)
        self.menuAdd_TestCase_Seq.addAction(self.actionReportBug)
        self.menubar.addAction(self.menuAdd_TestCase_Seq.menuAction())

        self.retranslateUi(LowerTester)
        self.EtmServiceTab.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(LowerTester)

    def retranslateUi(self, LowerTester):
        _translate = QtCore.QCoreApplication.translate
        LowerTester.setWindowTitle(_translate("LowerTester", "MainWindow"))
        self.groupBox.setTitle(_translate("LowerTester", "Settings"))
        self.myIP.setText(_translate("LowerTester", "fd53:7cb8:0383:000e::3aa"))
        self.label.setText(_translate("LowerTester", "Upper tester Address    "))
        self.label_2.setText(_translate("LowerTester", "Eth Adopter"))
        self.portNum.setText(_translate("LowerTester", "50444"))
        self.label_6.setText(_translate("LowerTester", "Etm Port"))
        self.Button_connect.setText(_translate("LowerTester", "Connect"))
        self.etmIpAddr.setToolTip(_translate("LowerTester", "<html><head/><body><p>Add Upper Tester IP address (IPV6)</p></body></html>"))
        self.etmIpAddr.setText(_translate("LowerTester", "fd53:7cb8:383:e::73"))
        self.label_5.setText(_translate("LowerTester", "My IpAddress"))
        self.groupBox_2.setTitle(_translate("LowerTester", "Etm Services"))
        self.Button_startTest.setText(_translate("LowerTester", "Start Test"))
        self.Button_endTest.setText(_translate("LowerTester", "End Test"))
        self.versionGetResult.setText(_translate("LowerTester", "Result:##  Version:##.##"))
        self.Button_getVersion.setText(_translate("LowerTester", "GetVersion"))
        self.EtmServiceTab.setTabText(self.EtmServiceTab.indexOf(self.VersionGet), _translate("LowerTester", "Get Version"))
        self.crAndBindConnection.setText(_translate("LowerTester", "TCP"))
        self.label_4.setText(_translate("LowerTester", "Local Port"))
        self.label_7.setText(_translate("LowerTester", "Bind?"))
        self.label_3.setText(_translate("LowerTester", "IP Addr"))
        self.Button_createAndBind.setText(_translate("LowerTester", "Create And Bind"))
        self.crAndBindLocalIpAddr.setText(_translate("LowerTester", "fd53:7cb8:383:e::73"))
        self.createBindResult.setText(_translate("LowerTester", "Result:##  SocketId:##"))
        self.label_18.setText(_translate("LowerTester", "Connection"))
        self.CrAndBindLocalPort.setText(_translate("LowerTester", "1234"))
        self.EtmServiceTab.setTabText(self.EtmServiceTab.indexOf(self.tab_2), _translate("LowerTester", "Create and Bind"))
        self.label_12.setText(_translate("LowerTester", "Socket ID"))
        self.closeSocketID.setText(_translate("LowerTester", "0"))
        self.Button_closeSocket.setText(_translate("LowerTester", "Close Socket"))
        self.closeSocketResult.setText(_translate("LowerTester", "Result:##"))
        self.label_13.setText(_translate("LowerTester", "Abort"))
        self.EtmServiceTab.setTabText(self.EtmServiceTab.indexOf(self.tab), _translate("LowerTester", "Close Socket"))
        self.Button_sendData.setText(_translate("LowerTester", "Send Data"))
        self.label_11.setText(_translate("LowerTester", "Data"))
        self.sendDataSocId.setText(_translate("LowerTester", "0"))
        self.label_8.setText(_translate("LowerTester", "Dest IP"))
        self.sendDataData.setText(_translate("LowerTester", "ABCDEFGHI"))
        self.sendDataResult.setToolTip(_translate("LowerTester", "<html><head/><body><p>Please note: because of the non-blocking behavior of Service Primitives a positive response does NOT signal the success of the transmission, but the success of issuing the transmission.</p></body></html>"))
        self.sendDataResult.setText(_translate("LowerTester", "Result:##"))
        self.label_9.setText(_translate("LowerTester", "Dest Port"))
        self.label_10.setText(_translate("LowerTester", "Socket ID"))
        self.sendDataDestIP.setText(_translate("LowerTester", "fd53:7cb8:383:e::73"))
        self.sendDataPort.setText(_translate("LowerTester", "1234"))
        self.EtmServiceTab.setTabText(self.EtmServiceTab.indexOf(self.tab_3), _translate("LowerTester", "Send Data"))
        self.label_14.setText(_translate("LowerTester", "Socket ID"))
        self.label_15.setText(_translate("LowerTester", "Max payload len"))
        self.rcvFwdMaxFwd.setText(_translate("LowerTester", "16"))
        self.rcvFwdResult.setText(_translate("LowerTester", "Result :Unknown Drop Count :##"))
        self.rcvFwdSocketId.setText(_translate("LowerTester", "0"))
        self.rcvFwdMaxLen.setText(_translate("LowerTester", "16"))
        self.Button_recvAndFwd.setText(_translate("LowerTester", "Receive and Forward"))
        self.label_16.setText(_translate("LowerTester", "Max Rec len"))
        self.EtmServiceTab.setTabText(self.EtmServiceTab.indexOf(self.widget), _translate("LowerTester", "Receive and forward"))
        self.label_33.setText(_translate("LowerTester", "Paylaod to send"))
        self.rcvFwdSourcePort.setText(_translate("LowerTester", "SourcePort: ##"))
        self.dummyTestPayload.setText(_translate("LowerTester", "ABCD1234"))
        self.rcvFwdTotalLength.setText(_translate("LowerTester", "Length:##"))
        self.rcvFwdAddr.setText(_translate("LowerTester", "Address :####:####:####:####:####"))
        self.label_34.setText(_translate("LowerTester", "Payload Rcvd"))
        self.rcvFwdpayload.setText(_translate("LowerTester", "-----------------------------------------------------"))
        self.rcvFwdSendDummy.setToolTip(_translate("LowerTester", "<html><head/><body><p>This send a dummy data &quot;ABCD1234&quot;</p></body></html>"))
        self.rcvFwdSendDummy.setText(_translate("LowerTester", "Test"))
        self.EtmServiceTab.setTabText(self.EtmServiceTab.indexOf(self.tab_4), _translate("LowerTester", "Test"))
        self.groupBox_3.setTitle(_translate("LowerTester", "Console output logs"))
        self.console.setHtml(_translate("LowerTester", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS UI Gothic\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p align=\"justify\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; color:#00ffff;\">Etm tester Beta v .1.1</span></p></body></html>"))
        self.menuAdd_TestCase_Seq.setTitle(_translate("LowerTester", "Menu"))
        self.actionHide_Console.setText(_translate("LowerTester", "Hide Console"))
        self.actionAdd_TestCase_Seq.setText(_translate("LowerTester", "Add TestCase Seq"))
        self.actionHide_Console_2.setText(_translate("LowerTester", "Hide Console"))
        self.actionShow_Console.setText(_translate("LowerTester", "Show Console"))
        self.actionClear_Console.setText(_translate("LowerTester", "Clear Console"))
        self.actionSave_Console_logs.setText(_translate("LowerTester", "Save Console logs"))
        self.actionReportBug.setText(_translate("LowerTester", "ReportBug"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    LowerTester = QtWidgets.QMainWindow()
    ui = Ui_LowerTester()
    ui.setupUi(LowerTester)
    LowerTester.show()
    sys.exit(app.exec_())
