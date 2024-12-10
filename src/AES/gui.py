from tkinter import Tk, ttk
from AES import AES

class AES_GUI:
    def __init__(self) -> None:        
        self.root = Tk()
        self.root.title("AES Encryption and Decryption")
        self.root.geometry("400x300")  # Set a fixed window size for better layout control        
    
    def create_button(self, text, command=None,row=4,pady=10,padx=10):
        btn = ttk.Button(self.root, text=text, command=command)
        btn.grid(row=row, column=0, columnspan=2, pady=pady, padx=padx)

    def create_text(self, width=10):
        entry = ttk.Entry(self.root, width=width)
        entry.grid(pady=5, padx=10, sticky='w')
        return entry
    
    def create_label(self, text):
        label = ttk.Label(self.root, text=text)
        label.grid(pady=5, padx=10, sticky='w')
    
    def get_text(self, entry):
        return entry.get()
    
    def main(self):
        # Create label and text entry for AES mode
        self.create_label("AES Mode (128/192/256):")
        self.AESMODE_entry = self.create_text(width=50)
        
        # Create label and text entry for text to encrypt
        self.create_label("Text to Encrypt:")
        self.text_entry = self.create_text(width=50)
        
        # Create label and text entry for encryption key
        self.create_label("Encryption Key:")
        self.key_entry = self.create_text(width=50)
                
        self.create_button("Encrypt", command=self.aes_encryption,pady=10,padx=10)
        
        self.create_button("Decrypt", command=self.aes_decryption,row=6,pady=10,padx=10)
        
    def aes_encryption(self):
        aes_mode = int(self.get_text(self.AESMODE_entry))
        self.aes = AES(aes_mode)
        self.cyphertext = self.aes.Encryption(self.get_text(self.text_entry), self.get_text(self.key_entry))
        
        print("Encrypted Text:")
        print(self.cyphertext)
        
    def aes_decryption(self):
        aes_mode = int(self.get_text(self.AESMODE_entry))
        self.aes = AES(aes_mode)        
        self.plaintext = self.aes.Decryption(self.cyphertext, self.get_text(self.key_entry))
                
        print("\nDecrypted Text:")
        print(self.plaintext)
        
    def run(self):
        self.root.mainloop()
