from tkinter import Tk, ttk
from AES import AES

class AES_GUI:
    def __init__(self) -> None:        
        self.root = Tk()
        self.root.title("AES Encryption and Decryption")
        self.root.geometry("400x300")  # Set a fixed window size for better layout control
        self.values = []
    
    def create_button(self, text, command=None):
        btn = ttk.Button(self.root, text=text, command=command)
        btn.grid(row=4, column=0, columnspan=2, pady=10, padx=10)

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
        
        # Create the submit button
        self.create_button("Encrypt", command=self.aes_process)
    
    def aes_process(self):
        aes_mode = int(self.get_text(self.AESMODE_entry))
        self.aes = AES(aes_mode)
        cyphertext = self.aes.Encryption(self.get_text(self.text_entry), self.get_text(self.key_entry))
        plaintext = self.aes.Decryption(cyphertext, self.get_text(self.key_entry))
        
        print("Encrypted Text:")
        print(cyphertext)
        print("\nDecrypted Text:")
        print(plaintext)
        
    def run(self):
        self.root.mainloop()
