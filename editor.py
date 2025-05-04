import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QTextEdit, 
                               QFileDialog, QMessageBox, QInputDialog, QDialog,
                               QLabel, QLineEdit, QPushButton, QVBoxLayout)
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtCore import Qt, QFileInfo
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import argparse

class PasswordDialog(QDialog):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowModality(Qt.ApplicationModal)
        
        layout = QVBoxLayout()
        
        self.label = QLabel("Введите пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        
        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.ok_button)
        
        self.setLayout(layout)
    
    def get_password(self):
        return self.password_input.text() if self.exec() == QDialog.Accepted else None

class MDCEditor(QMainWindow):
    def __init__(self, file_to_open=None):
        super().__init__()
        self.setWindowTitle("MDC Editor (Password Protected)")
        self.setGeometry(100, 100, 800, 600)
        
        self.text_edit = QTextEdit()
        self.setCentralWidget(self.text_edit)
        
        self.create_menu()
        self.current_file = None
        
        # Если указан файл для открытия
        if file_to_open and os.path.exists(file_to_open):
            self.open_file_direct(file_to_open)
    
    def open_file_direct(self, filename):
        """Открывает файл напрямую (при запуске через ассоциацию файлов)"""
        password = self.get_password("Открытие файла")
        if not password:
            return
            
        try:
            with open(filename, "rb") as f:
                salt = f.read(16)
                encrypted = f.read()
                
                key = self.generate_key_from_password(password, salt)
                cipher = Fernet(key)
                
                decrypted = cipher.decrypt(encrypted).decode()
                self.text_edit.setPlainText(decrypted)
                self.current_file = filename
                self.setWindowTitle(f"MDC Editor - {os.path.basename(filename)}")
                
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", "Неверный пароль или поврежденный файл")
    
    def get_password(self, title):
        dialog = PasswordDialog(title, self)
        dialog.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        return dialog.get_password()
    
    def generate_key_from_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def open_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Открыть файл", "", "MDC Files (*.mdc)")
        if not filename:
            return
            
        self.open_file_direct(filename)
    
    def save_file(self):
        if self.current_file:
            password = self.get_password("Введите пароль для сохранения")
            if password:
                self._save_to_file(self.current_file, password)
        else:
            self.save_file_as()
    
    def save_file_as(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Сохранить файл", "", "MDC Files (*.mdc)")
        if not filename:
            return
            
        if not filename.endswith(".mdc"):
            filename += ".mdc"
            
        password = self.get_password("Создать пароль для файла")
        if not password:
            return
            
        self._save_to_file(filename, password)
        self.current_file = filename
        self.setWindowTitle(f"MDC Editor - {os.path.basename(filename)}")
    
    def _save_to_file(self, filename, password):
        try:
            text = self.text_edit.toPlainText()
            salt = os.urandom(16)
            key = self.generate_key_from_password(password, salt)
            cipher = Fernet(key)
            
            encrypted = cipher.encrypt(text.encode())
            
            with open(filename, "wb") as f:
                f.write(salt)
                f.write(encrypted)
                
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения: {str(e)}")
    
    def create_menu(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("Файл")
        
        new_action = QAction("Новый", self)
        new_action.triggered.connect(self.new_file)
        new_action.setShortcut(QKeySequence.New)
        file_menu.addAction(new_action)
        
        open_action = QAction("Открыть...", self)
        open_action.triggered.connect(self.open_file)
        open_action.setShortcut(QKeySequence.Open)
        file_menu.addAction(open_action)
        
        save_action = QAction("Сохранить", self)
        save_action.triggered.connect(self.save_file)
        save_action.setShortcut(QKeySequence.Save)
        file_menu.addAction(save_action)
        
        save_as_action = QAction("Сохранить как...", self)
        save_as_action.triggered.connect(self.save_file_as)
        file_menu.addAction(save_as_action)
    
    def new_file(self):
        self.text_edit.clear()
        self.current_file = None
        self.setWindowTitle("MDC Editor (Password Protected)")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', nargs='?', help='File to open')
    args = parser.parse_args()
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    editor = MDCEditor(args.file)
    editor.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()