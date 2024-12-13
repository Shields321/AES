from AES.AES import AES

AESMODE = None
while True:
    try:
        AESMODE = int(input("Enter the AES Mode (128/192/256): "))
        if AESMODE ==128 or AESMODE == 192 or AESMODE == 256:
            break   
        raise ValueError("Error")     
    except Exception as e:
        print(f"value of {AESMODE} is not one of the types supported")
    
text = input("Enter the text you wish to encrypt: ")
key = input("Enter the Key for the encryption: ")

aes = AES(AESMODE=AESMODE)
cyphertext = aes.Encryption(text,key)
print('Encrypted text')
print(cyphertext) 

decryptedtext = aes.Decryption(cyphertext,key)
print('Decrypted text')
print(decryptedtext)