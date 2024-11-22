from AES_Encryption import Encryption
from AES_Decryption import Decryption
AESMODE = 128
aesE = Encryption(AESMODE=AESMODE)
aesD = Decryption(AESMODE=AESMODE)
key = "Thats my Kung Fu"
cypherText = aesE.Encryption("Two One Nine Two",key)
aesD.Decryption(cypherText,key)
