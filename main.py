#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import ipaddress
import netifaces as ni
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class ClickToCopyLineEdit(QLineEdit):
    def __init__(self, parent=None):
        super().__init__(parent)

    def mousePressEvent(self, event):
        QApplication.clipboard().setText(self.text())
        super().mousePressEvent(event)

class LanCalculator(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Main layout
        main_layout = QVBoxLayout()
        self.setWindowTitle('IPv4 LAN Calculator')

        # Define the width for all input elements and font
        input_width = 200
        font = QFont('Ubuntu', 13)

        # Style for read-only fields
        readonly_style = "QLineEdit { background-color: #f0f0f0; color: #333; text-align: right; }"

        # IP Address Input
        ip_layout = QHBoxLayout()
        ip_label = QLabel("IP Address")
        ip_label.setFont(font)
        self.ip_input = QLineEdit(self)
        self.ip_input.setFont(font)
        self.ip_input.setFixedWidth(input_width)
        self.ip_input.setAlignment(Qt.AlignRight)
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_input)
        main_layout.addLayout(ip_layout)

        # Network Mask Selector
        network_layout = QHBoxLayout()
        network_label = QLabel("Network")
        network_label.setFont(font)
        self.network_selector = QComboBox(self)
        self.network_selector.setFont(font)
        for cidr in range(33):
            mask = str(ipaddress.IPv4Network(f'0.0.0.0/{cidr}', strict=False).netmask)
            self.network_selector.addItem(f'{cidr}/{mask}')
        self.network_selector.setFixedWidth(input_width)
        network_layout.addWidget(network_label)
        network_layout.addWidget(self.network_selector)
        main_layout.addLayout(network_layout)

        # Set default values from system
        self.set_default_values()

        # Calculate Button
        self.calc_button = QPushButton('Calculate', self)
        self.calc_button.setFont(font)
        self.calc_button.clicked.connect(self.calculate_network)
        main_layout.addWidget(self.calc_button)

        # Output fields initialization
        self.network_output = ClickToCopyLineEdit(self)
        self.broadcast_output = ClickToCopyLineEdit(self)
        self.hostmin_output = ClickToCopyLineEdit(self)
        self.hostmax_output = ClickToCopyLineEdit(self)
        self.hosts_output = ClickToCopyLineEdit(self)

        # Apply read-only style and add output fields to the layout
        for field in [self.network_output, self.broadcast_output, self.hostmin_output, self.hostmax_output, self.hosts_output]:
            field.setReadOnly(True)
            field.setStyleSheet(readonly_style)
            field.setAlignment(Qt.AlignRight)  # Align text to the right
            field.setFont(font)
            field.setFixedWidth(input_width)  # Set fixed width to align with other input fields

        # Adding output fields to the layout
        self.add_output_field(main_layout, "Network", self.network_output)
        self.add_output_field(main_layout, "Broadcast", self.broadcast_output)
        self.add_output_field(main_layout, "Hostmin", self.hostmin_output)
        self.add_output_field(main_layout, "Hostmax", self.hostmax_output)
        self.add_output_field(main_layout, "Hosts", self.hosts_output)

        # Set Layout
        self.setLayout(main_layout)

    def set_default_values(self):
        try:
            gateways = ni.gateways()
            default_interface = gateways['default'][ni.AF_INET][1]
            addrs = ni.ifaddresses(default_interface)
            ip_info = addrs[ni.AF_INET][0]
            default_ip = ip_info['addr']
            netmask = ip_info['netmask']
            default_cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])

            self.ip_input.setText(default_ip)
            self.network_selector.setCurrentIndex(default_cidr)
        except Exception as e:
            print("Could not determine default network settings:", e)

    def add_output_field(self, layout, label_text, line_edit):
        field_layout = QHBoxLayout()
        label = QLabel(label_text)
        label.setFont(QFont('Ubuntu', 13))
        line_edit.setReadOnly(True)
        field_layout.addWidget(label)
        field_layout.addWidget(line_edit)
        layout.addLayout(field_layout)

    def calculate_network(self):
        try:
            ip_addr = self.ip_input.text()
            network_cidr = int(self.network_selector.currentText().split('/')[0])
            network = ipaddress.IPv4Network(f'{ip_addr}/{network_cidr}', strict=False)

            # Set results in the output fields
            self.network_output.setText(str(network.network_address))
            self.broadcast_output.setText(str(network.broadcast_address))
            self.hostmin_output.setText(str(min(network.hosts(), default='N/A')))
            self.hostmax_output.setText(str(max(network.hosts(), default='N/A')))
            self.hosts_output.setText(str(network.num_addresses - 2 if network.num_addresses > 2 else 'N/A'))
        except ValueError as e:
            QMessageBox.critical(self, 'Error', str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = LanCalculator()
    ex.show()
    sys.exit(app.exec_())
