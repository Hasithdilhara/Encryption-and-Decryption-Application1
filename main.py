import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class EncryptWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Encryption Window")
        self.geometry("400x500")
        self.configure(bg='#90EE90')  # Light green background
        
        # Window title
        tk.Label(
            self,
            text="Enter Text to Encrypt:",
            bg='#90EE90',
            font=('Arial', 12)
        ).pack(pady=10)
        
        # Input text area
        self.text_frame = tk.Frame(self, bg='#90EE90')
        self.text_frame.pack(pady=5)
        
        self.plaintext_entry = tk.Text(
            self.text_frame,
            height=4,
            width=40,
            font=('Arial', 10)
        )
        self.plaintext_entry.pack()
        
        # Key entry label and frame
        self.key_frame = tk.Frame(self, bg='#90EE90')
        self.key_frame.pack(pady=10)
        
        tk.Label(
            self.key_frame,
            text="Enter Key (16 characters):",
            bg='#90EE90',
            font=('Arial', 12)
        ).pack()
        
        # Key entry (with password masking)
        self.key_entry = tk.Entry(
            self.key_frame,
            width=30,
            show='*',
            font=('Arial', 10)
        )
        self.key_entry.pack(pady=5)
        
        # Encrypt button
        self.encrypt_button = tk.Button(
            self,
            text="Encrypt",
            command=self.encrypt_text,
            bg='blue',
            fg='white',
            width=15,
            font=('Arial', 10)
        )
        self.encrypt_button.pack(pady=10)
        
        # Result text box
        self.result_text = tk.Text(
            self,
            height=4,
            width=40,
            font=('Arial', 10),
            wrap=tk.WORD
        )
        self.result_text.pack(pady=10)
    
    def encrypt_text(self):
        try:
            plaintext = self.plaintext_entry.get("1.0", tk.END).strip()
            key = self.key_entry.get().strip()
            
            if not plaintext or not key:
                messagebox.showerror("Error", "1234567812345678")
                return
                
            if len(key) != 16:
                messagebox.showerror("Error", "1234567812345678")
                return
            
            # Generate a key from the password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'static_salt',
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
            
            # Create Fernet instance and encrypt
            f = Fernet(key)
            encrypted_text = f.encrypt(plaintext.encode())
            
            # Display result
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', encrypted_text.decode())
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

class DecryptWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Decryption Window")
        self.geometry("400x500")
        self.configure(bg='#FFB6C1')  # Light pink background
        
        # Window title
        tk.Label(
            self,
            text="Enter Ciphertext to Decrypt:",
            bg='#FFB6C1',
            font=('Arial', 12)
        ).pack(pady=10)
        
        # Input text area
        self.text_frame = tk.Frame(self, bg='#FFB6C1')
        self.text_frame.pack(pady=5)
        
        self.ciphertext_entry = tk.Text(
            self.text_frame,
            height=4,
            width=40,
            font=('Arial', 10)
        )
        self.ciphertext_entry.pack()
        
        # Key entry label and frame
        self.key_frame = tk.Frame(self, bg='#FFB6C1')
        self.key_frame.pack(pady=10)
        
        tk.Label(
            self.key_frame,
            text="Enter Key (16 characters):",
            bg='#FFB6C1',
            font=('Arial', 12)
        ).pack()
        
        # Key entry (with password masking)
        self.key_entry = tk.Entry(
            self.key_frame,
            width=30,
            show='*',
            font=('Arial', 10)
        )
        self.key_entry.pack(pady=5)
        
        # Decrypt button
        self.decrypt_button = tk.Button(
            self,
            text="Decrypt",
            command=self.decrypt_text,
            bg='blue',
            fg='white',
            width=15,
            font=('Arial', 10)
        )
        self.decrypt_button.pack(pady=10)
        
        # Result text box
        self.result_text = tk.Text(
            self,
            height=4,
            width=40,
            font=('Arial', 10),
            wrap=tk.WORD
        )
        self.result_text.pack(pady=10)
    
    def decrypt_text(self):
        try:
            ciphertext = self.ciphertext_entry.get("1.0", tk.END).strip()
            key = self.key_entry.get().strip()
            
            if not ciphertext or not key:
                messagebox.showerror("Error", "Please enter both ciphertext and key")
                return
                
            if len(key) != 16:
                messagebox.showerror("Error", "Key must be exactly 16 characters")
                return
            
            # Generate the same key from the password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'static_salt',
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
            
            # Create Fernet instance and decrypt
            f = Fernet(key)
            decrypted_text = f.decrypt(ciphertext.encode())
            
            # Display result
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', decrypted_text.decode())
            
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed: Invalid key or ciphertext")

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES Encryption and Decryption")
        self.geometry("400x200")
        self.configure(bg='lightblue')
        
        # Title
        tk.Label(
            self,
            text="AES Encryption/Decryption",
            bg='lightblue',
            font=('Arial', 14, 'bold')
        ).pack(pady=20)
        
        # Create main buttons
        tk.Button(
            self, 
            text="Open Encryption Window", 
            command=self.open_encrypt_window,
            bg='green',
            fg='white',
            width=20,
            height=1,
            font=('Arial', 10)
        ).pack(pady=10)
        
        tk.Button(
            self, 
            text="Open Decryption Window", 
            command=self.open_decrypt_window,
            bg='red',
            fg='white',
            width=20,
            height=1,
            font=('Arial', 10)
        ).pack(pady=10)
    
    def open_encrypt_window(self):
        EncryptWindow(self)
    
    def open_decrypt_window(self):
        DecryptWindow(self)

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()