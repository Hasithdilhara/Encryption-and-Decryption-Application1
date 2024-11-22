import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

class EncryptWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("DES Encryption Window")
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
            text="Enter Key (8 characters):",
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
        tk.Label(
            self,
            text="Encrypted Result:",
            bg='#90EE90',
            font=('Arial', 12)
        ).pack(pady=5)
        
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
                messagebox.showerror("Error", "12345678")
                return
                
            if len(key) != 8:
                messagebox.showerror("Error", "12345678")
                return
            
            # Create cipher object and encrypt the data
            cipher = DES.new(key.encode(), DES.MODE_ECB)
            padded_text = pad(plaintext.encode(), DES.block_size)
            encrypted_text = cipher.encrypt(padded_text)
            
            # Convert to base64 for display
            result = base64.b64encode(encrypted_text).decode()
            
            # Display result
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', result)
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

class DecryptWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("DES Decryption Window")
        self.geometry("400x500")
        self.configure(bg='#FFB6C1')  # Light pink background
        
        # Window title
        tk.Label(
            self,
            text="Enter Text to Decrypt:",
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
            text="Enter Key (8 characters):",
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
        tk.Label(
            self,
            text="Decrypted Result:",
            bg='#FFB6C1',
            font=('Arial', 12)
        ).pack(pady=5)
        
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
                messagebox.showerror("Error", "Please enter both text and key")
                return
                
            if len(key) != 8:
                messagebox.showerror("Error", "Key must be exactly 8 characters")
                return
            
            # Decode from base64 and decrypt
            encrypted_data = base64.b64decode(ciphertext)
            cipher = DES.new(key.encode(), DES.MODE_ECB)
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # Remove padding and convert to string
            result = unpad(decrypted_data, DES.block_size).decode()
            
            # Display result
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', result)
            
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed: Invalid key or ciphertext")

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DES Encryption and Decryption")
        self.geometry("400x200")
        self.configure(bg='lightblue')
        
        # Title
        tk.Label(
            self,
            text="DES Encryption/Decryption",
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