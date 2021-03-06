# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setWindowModality(QtCore.Qt.WindowModal)
        MainWindow.resize(1129, 216)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.username_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.username_2.setObjectName("username_2")
        self.horizontalLayout_2.addWidget(self.username_2)
        self.password = QtWidgets.QLineEdit(self.centralwidget)
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password.setObjectName("password")
        self.horizontalLayout_2.addWidget(self.password)
        self.ip = QtWidgets.QLineEdit(self.centralwidget)
        self.ip.setObjectName("ip")
        self.horizontalLayout_2.addWidget(self.ip)
        self.cmd = QtWidgets.QComboBox(self.centralwidget)
        self.cmd.setObjectName("cmd")
        self.cmd.addItem("")
        self.cmd.addItem("")
        self.cmd.addItem("")
        self.horizontalLayout_2.addWidget(self.cmd)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.policy = QtWidgets.QLineEdit(self.centralwidget)
        self.policy.setObjectName("policy")
        self.horizontalLayout_3.addWidget(self.policy)
        self.targets = QtWidgets.QLineEdit(self.centralwidget)
        self.targets.setEchoMode(QtWidgets.QLineEdit.Normal)
        self.targets.setObjectName("targets")
        self.horizontalLayout_3.addWidget(self.targets)
        self.name_prefix = QtWidgets.QLineEdit(self.centralwidget)
        self.name_prefix.setObjectName("name_prefix")
        self.horizontalLayout_3.addWidget(self.name_prefix)
        self.grp_name = QtWidgets.QLineEdit(self.centralwidget)
        self.grp_name.setObjectName("grp_name")
        self.horizontalLayout_3.addWidget(self.grp_name)
        self.verticalLayout_2.addLayout(self.horizontalLayout_3)
        self.verticalLayout_3.addLayout(self.verticalLayout_2)
        self.verticalLayout_4.addLayout(self.verticalLayout_3)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.verify = QtWidgets.QCheckBox(self.centralwidget)
        self.verify.setObjectName("verify")
        self.horizontalLayout_5.addWidget(self.verify)
        self.install = QtWidgets.QCheckBox(self.centralwidget)
        self.install.setObjectName("install")
        self.horizontalLayout_5.addWidget(self.install)
        self.verify_and_install = QtWidgets.QCheckBox(self.centralwidget)
        self.verify_and_install.setObjectName("verify_and_install")
        self.horizontalLayout_5.addWidget(self.verify_and_install)
        self.add_new_hosts = QtWidgets.QCheckBox(self.centralwidget)
        self.add_new_hosts.setObjectName("add_new_hosts")
        self.horizontalLayout_5.addWidget(self.add_new_hosts)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem)
        self.verticalLayout_4.addLayout(self.horizontalLayout_5)
        spacerItem1 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_4.addItem(spacerItem1)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem2)
        self.logout = QtWidgets.QToolButton(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.logout.sizePolicy().hasHeightForWidth())
        self.logout.setSizePolicy(sizePolicy)
        self.logout.setMinimumSize(QtCore.QSize(101, 31))
        self.logout.setObjectName("logout")
        self.horizontalLayout_4.addWidget(self.logout)
        self.toolButton = QtWidgets.QToolButton(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.toolButton.sizePolicy().hasHeightForWidth())
        self.toolButton.setSizePolicy(sizePolicy)
        self.toolButton.setMinimumSize(QtCore.QSize(101, 31))
        self.toolButton.setObjectName("toolButton")
        self.horizontalLayout_4.addWidget(self.toolButton)
        self.start = QtWidgets.QToolButton(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.start.sizePolicy().hasHeightForWidth())
        self.start.setSizePolicy(sizePolicy)
        self.start.setMinimumSize(QtCore.QSize(161, 31))
        self.start.setObjectName("start")
        self.horizontalLayout_4.addWidget(self.start)
        self.verticalLayout_4.addLayout(self.horizontalLayout_4)
        self.verticalLayout_4.setStretch(0, 6)
        self.verticalLayout_4.setStretch(1, 1)
        self.verticalLayout_4.setStretch(2, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Checkpoint Importer"))
        self.username_2.setPlaceholderText(_translate("MainWindow", "Username"))
        self.password.setPlaceholderText(_translate("MainWindow", "Password"))
        self.ip.setPlaceholderText(_translate("MainWindow", "Management IP"))
        self.cmd.setCurrentText(_translate("MainWindow", "no action"))
        self.cmd.setItemText(0, _translate("MainWindow", "no action"))
        self.cmd.setItemText(1, _translate("MainWindow", "add-group"))
        self.cmd.setItemText(2, _translate("MainWindow", "set-group"))
        self.policy.setPlaceholderText(_translate("MainWindow", "Policy Name"))
        self.targets.setPlaceholderText(_translate("MainWindow", "target to install policy on, seperated by [,]: fw, fw2"))
        self.name_prefix.setPlaceholderText(_translate("MainWindow", "name prefix for objects"))
        self.grp_name.setPlaceholderText(_translate("MainWindow", "group name"))
        self.verify.setText(_translate("MainWindow", "Verify"))
        self.install.setText(_translate("MainWindow", "Install"))
        self.verify_and_install.setText(_translate("MainWindow", "Verify and Install"))
        self.add_new_hosts.setText(_translate("MainWindow", "Add new hosts"))
        self.logout.setText(_translate("MainWindow", "Logout Session"))
        self.toolButton.setText(_translate("MainWindow", "Import File"))
        self.start.setText(_translate("MainWindow", "Start"))
