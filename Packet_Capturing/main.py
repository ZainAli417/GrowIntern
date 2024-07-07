#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul  6 09:57:25 2024

@author: zanonymous
"""

import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QHBoxLayout, QWidget, QLabel, QSizePolicy
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot, Qt, QTimer
from PyQt5.QtGui import QPixmap
from pyqtgraph import PlotWidget, mkPen
from packet_capture import packet_callback, start_sniffing
import time
import collections

class SniffingThread(QThread):
    packet_received = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.sniffing = False

    def run(self):
        start_sniffing(self.packet_callback)

    def packet_callback(self, packet):
        formatted_packet = packet_callback(packet)
        self.packet_received.emit(formatted_packet)
        time.sleep(1)  # Slow down the capturing for real-time depiction

class PacketAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.sniffing = False
        self.packet_count = 0
        self.graph_data = collections.deque(maxlen=100)
        self.sniffing_thread = SniffingThread()
        self.sniffing_thread.packet_received.connect(self.packet_callback_wrapper)
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)

    def initUI(self):
        self.setWindowTitle('Packet Network Analyzer')
        self.setGeometry(100, 100, 1920, 1080)  # Full-screen dimensions

        # Full-screen mode
        self.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint | Qt.WindowCloseButtonHint)
        self.showFullScreen()

        # Central widget and layout
        centralWidget = QWidget(self)
        self.setCentralWidget(centralWidget)
        mainLayout = QVBoxLayout(centralWidget)

        # Buttons layout
        buttonLayout = QHBoxLayout()
        mainLayout.addLayout(buttonLayout)

        # Start button
        self.startButton = QPushButton('Start', self)
        self.startButton.setStyleSheet("background-color: green; border-radius: 10px; padding: 10px; font-size: 20px; font-weight: bold;")
        self.startButton.clicked.connect(self.start_sniffing)
        buttonLayout.addWidget(self.startButton)

        # Stop button
        self.stopButton = QPushButton('Stop', self)
        self.stopButton.setStyleSheet("background-color: red; border-radius: 10px; padding: 10px; font-size: 20px; font-weight: bold;")
        self.stopButton.clicked.connect(self.stop_sniffing)
        buttonLayout.addWidget(self.stopButton)
        # Add logo image next to TCP table
        tcpLogo = QLabel(self)
        pixmap = QPixmap('/home/zanonymous/Downloads/logo.png')  # Replace with your TCP logo path

        # Resize the pixmap to your desired size
        desired_width = 350  # Set your desired width
        desired_height = 900  # Set your desired height
        pixmap = pixmap.scaled(desired_width, desired_height, Qt.KeepAspectRatio, Qt.SmoothTransformation)

        
        
        # Labels for tables
        self.tcpLabel = QLabel('TCP Layer Table')
        self.tcpLabel.setStyleSheet("font-size: 20px; font-weight: bold;")
        mainLayout.addWidget(self.tcpLabel)

        # Layout for TCP layer table and logo
        tcpLayout = QHBoxLayout()
        mainLayout.addLayout(tcpLayout)

        # Table widget for TCP layer packet data
        self.tcpTable = QTableWidget(self)
        self.tcpTable.setColumnCount(8)
        self.tcpTable.setHorizontalHeaderLabels(['Packet Number', 'Sport', 'Dport', 'Seq', 'Ack', 'Dataofs', 'Reserved', 'Flag', 'Window'])
        tcpLayout.addWidget(self.tcpTable)

        tcpLogo.setPixmap(pixmap)
        tcpLogo.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        tcpLayout.addWidget(tcpLogo)

        self.ipLabel = QLabel('IP Layer Table')
        self.ipLabel.setStyleSheet("font-size: 20px; font-weight: bold;")
        mainLayout.addWidget(self.ipLabel)

        # Layout for IP layer table and logo
        ipLayout = QHBoxLayout()
        mainLayout.addLayout(ipLayout)

        # Table widget for IP layer packet data
        self.ipTable = QTableWidget(self)
        self.ipTable.setColumnCount(13)
        self.ipTable.setHorizontalHeaderLabels(['Packet Number', 'Version', 'IHL', 'TOS', 'Len', 'ID', 'Flags', 'Frag', 'TTL', 'Proto', 'Checksum', 'Src', 'Dst', 'Options'])
        ipLayout.addWidget(self.ipTable)

     

        # Graph widget
        self.graphWidget = PlotWidget(self)
        self.graphWidget.setBackground('w')
        self.graphWidget.setTitle("Packet Capture", color="b", size="18pt")
        self.graphWidget.setLabel('left', 'Packet Count', color='red', size=25)
        self.graphWidget.setLabel('bottom', 'Time', color='red', size=25)
        self.graphWidget.showGrid(x=True, y=True)
        self.graphWidget.addLegend()
        self.pen = mkPen(color=(255, 0, 0), width=4)
        mainLayout.addWidget(self.graphWidget)

    def start_sniffing(self):
        self.sniffing = True
        self.startButton.setStyleSheet("background-color: green; border-radius: 10px; padding: 10px; font-size: 20px; font-weight: bold;")
        self.stopButton.setStyleSheet("")
        self.packet_count = 0
        self.graph_data.clear()
        self.tcpTable.setRowCount(0)  # Clear TCP table
        self.ipTable.setRowCount(0)   # Clear IP table
        self.timer.start(1000)  # Update the graph every second
        if not self.sniffing_thread.isRunning():
            self.sniffing_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.startButton.setStyleSheet("")
        self.stopButton.setStyleSheet("background-color: red; border-radius: 10px; padding: 10px; font-size: 20px; font-weight: bold;")
        self.timer.stop()
        if self.sniffing_thread.isRunning():
            self.sniffing_thread.terminate()

    @pyqtSlot(str)
    def packet_callback_wrapper(self, formatted_packet):
        if self.sniffing:
            self.packet_count += 1
            self.graph_data.append(self.packet_count)

            # Parse packet data
            lines = formatted_packet.split('\n')
            tcp_data = [str(self.packet_count)]
            ip_data = [str(self.packet_count)]

            for line in lines:
                if 'sport' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'dport' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'seq' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'ack' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'dataofs' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'reserved' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'flags' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'window' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'version' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'ihl' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'tos' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'len' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'id' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'flags' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'frag' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'ttl' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'proto' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'chksum' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'src' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'dst' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'options' in line:
                    ip_data.append(line.split('=')[-1].strip())

            self.add_row_to_table(self.tcpTable, tcp_data)
            self.add_row_to_table(self.ipTable, ip_data)

    def add_row_to_table(self, table, data):
        row = table.rowCount()
        table.insertRow(row)
        for col, value in enumerate(data):
            table.setItem(row, col, QTableWidgetItem(value))

    def update_graph(self):
        self.graphWidget.clear()
        self.graphWidget.plot(list(range(len(self.graph_data))), list(self.graph_data), pen=self.pen)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PacketAnalyzer()
    ex.show()
    sys.exit(app.exec_())


    def start_sniffing(self):
        self.sniffing = True
        self.startButton.setStyleSheet("background-color: green; border-radius: 10px; padding: 10px; font-size: 20px; font-weight: bold;")
        self.stopButton.setStyleSheet("")
        self.packet_count = 0
        self.graph_data.clear()
        self.tcpTable.setRowCount(0)  # Clear TCP table
        self.ipTable.setRowCount(0)   # Clear IP table
        self.timer.start(1000)  # Update the graph every second
        if not self.sniffing_thread.isRunning():
            self.sniffing_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.startButton.setStyleSheet("")
        self.stopButton.setStyleSheet("background-color: red; border-radius: 10px; padding: 10px; font-size: 20px; font-weight: bold;")
        self.timer.stop()
        if self.sniffing_thread.isRunning():
            self.sniffing_thread.terminate()

    @pyqtSlot(str)
    def packet_callback_wrapper(self, formatted_packet):
        if self.sniffing:
            self.packet_count += 1
            self.graph_data.append(self.packet_count)

            # Parse packet data
            lines = formatted_packet.split('\n')
            tcp_data = [str(self.packet_count)]
            ip_data = [str(self.packet_count)]

            for line in lines:
                if 'sport' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'dport' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'seq' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'ack' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'dataofs' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'reserved' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'flags' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'window' in line:
                    tcp_data.append(line.split('=')[-1].strip())
                elif 'version' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'tos' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'len' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'id' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'flags' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'frag' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'ttl' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'proto' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'chksum' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'src' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'dst' in line:
                    ip_data.append(line.split('=')[-1].strip())
                elif 'options' in line:
                    ip_data.append(line.split('=')[-1].strip())

            self.add_row_to_table(self.tcpTable, tcp_data)
            self.add_row_to_table(self.ipTable, ip_data)

    def add_row_to_table(self, table, data):
        row = table.rowCount()
        table.insertRow(row)
        for col, value in enumerate(data):
            table.setItem(row, col, QTableWidgetItem(value))

    def update_graph(self):
        self.graphWidget.clear()
        self.graphWidget.plot(list(range(len(self.graph_data))), list(self.graph_data), pen=self.pen)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PacketAnalyzer()
    ex.show()
    sys.exit(app.exec_())
