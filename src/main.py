from AES import AES
from tkinter import ttk

AESMODE = 128
aes = AES(AESMODE=AESMODE)
key = "Thats my Kung Fu"

cyphertext = aes.Encryption("Two One Nine Two",key)
print('Encrypted text')
print(cyphertext) 

decryptedtext = aes.Decryption(cyphertext,key)
print('Decrypted text')
print(decryptedtext)
