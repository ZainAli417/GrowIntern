#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul  7 09:28:29 2024

@author: root
"""
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QProgressBar
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QIcon, QPixmap
from Password_Strength import calculate_password_strength

class PasswordStrengthTester(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Password Strength Tester')
        # Mobile screen dimensions 
        self.setGeometry(100, 100, 590, 1000)
        self.setStyleSheet("background-color: #071033;")

        # Main layout
        mainLayout = QVBoxLayout()
        self.setLayout(mainLayout)

        # Logo at the top center
        logo = QLabel(self)
        pixmap = QPixmap('resource/logo.png')
        # Resize the pixmap to your desired size
        desired_width = 250  # Set your desired width
        desired_height = 250  # Set your desired height
        pixmap = pixmap.scaled(desired_width, desired_height,
                               Qt.KeepAspectRatio, Qt.SmoothTransformation)

        logo.setPixmap(pixmap)
        logo.setAlignment(Qt.AlignCenter)
        mainLayout.addWidget(logo)

        # Title label
        title = QLabel('Password Strength Tester')
        title.setFont(QFont('Sans', 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: white;")
        mainLayout.addWidget(title)

        # Password input field with hide/unhide button
        inputLayout = QHBoxLayout()
        self.passwordInput = QLineEdit()
        self.passwordInput.setEchoMode(QLineEdit.Password)
        self.passwordInput.setPlaceholderText('Enter your password')
        self.passwordInput.textChanged.connect(self.update_strength)
        self.passwordInput.setStyleSheet("""
            border-radius: 50px;
            padding: 10px;
            font-size: 18px;
            background-color: white;
            color: black;
        """)
        inputLayout.addWidget(self.passwordInput)

        self.toggleButton = QPushButton()
        self.toggleButton.setIcon(QIcon('resource/hide.png'))
        self.toggleButton.setIconSize(QSize(70, 70))  # Set desired size
        self.toggleButton.setCheckable(True)
        self.toggleButton.setStyleSheet("""
            border: none;
            background: none;
            width: 70px;
            height: 70px;
        """)
        self.toggleButton.toggled.connect(self.toggle_password_visibility)
        inputLayout.addWidget(self.toggleButton)

        mainLayout.addLayout(inputLayout)

        # Strength label
        self.strengthLabel = QLabel('Strength: ')
        self.strengthLabel.setFont(QFont('sans', 15))
        self.strengthLabel.setStyleSheet("color: white;")
        mainLayout.addWidget(self.strengthLabel)

        # Strength bar
        self.strengthBar = QProgressBar()
        self.strengthBar.setRange(0, 100)
        self.strengthBar.setTextVisible(False)
        self.strengthBar.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 50px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                border-radius: 50px;
                background: qlineargradient(
                    spread:pad, x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff0000, stop:0.5 #ffff00, stop:1 #00ff00);
            }
        """)
        mainLayout.addWidget(self.strengthBar)

    def toggle_password_visibility(self, checked):
        if checked:
            self.passwordInput.setEchoMode(QLineEdit.Normal)
            self.toggleButton.setIcon(QIcon('resource/unhide.png'))
        else:
            self.passwordInput.setEchoMode(QLineEdit.Password)
            self.toggleButton.setIcon(QIcon('resource/hide.png'))

    def update_strength(self):
        password = self.passwordInput.text()
        strength, value = calculate_password_strength(password)
        self.strengthLabel.setText(f'Strength: {strength}')
        self.strengthBar.setValue(value)

        # Update strength label color
        if strength == 'Weak':
            self.strengthLabel.setStyleSheet("color: red;")
        elif strength == 'Medium':
            self.strengthLabel.setStyleSheet("color: yellow;")
        elif strength == 'Strong':
            self.strengthLabel.setStyleSheet("color: lightgreen;")
        elif strength == 'Extreme':
            self.strengthLabel.setStyleSheet("color: green;")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PasswordStrengthTester()
    window.show()
    sys.exit(app.exec_())
