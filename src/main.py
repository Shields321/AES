from AES import AES
from tkinter import ttk


text = input("Enter the text you wish to encrypt: ")
key = input("Enter the Key for the encryption: ")


AESMODE = 128     
aes = AES(AESMODE=AESMODE)
cyphertext = aes.Encryption(text,key)
print('Encrypted text')
print(cyphertext) 

decryptedtext = aes.Decryption(cyphertext,key)
print('Decrypted text')
print(decryptedtext)
