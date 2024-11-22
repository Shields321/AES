from AES_Encryption import Encryption
from AES_Decryption import Decryption

class AES:
    def __init__(self,AESMODE=128) -> None:        
        self.aesE = Encryption(AESMODE=AESMODE)
        self.aesD = Decryption(AESMODE=AESMODE) 
        self.AESOutput = None       
    def Encryption(self,plainText,key):
        self.AESOutput = self.aesE.Encryption(plainText,key) 
        return self.AESOutput       
    def Decryption(self,cyphertext,key):
        self.AESOutput = self.aesD.Decryption(cyphertext,key)
        return self.AESOutput