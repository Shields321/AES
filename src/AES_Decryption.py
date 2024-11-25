from SBOX import SBOX
from basic_functions import basic_functions
from Key_Expansion import Key_Expansion
import numpy as np
class Decryption():
    def __init__(self,AESMODE) -> None:
        self.sbox = SBOX()        
        self.functions = basic_functions()           
        self.keys = []
        self.key_rounds = {128:10, 192:12, 256:14}[AESMODE] 
        self.key_exp = Key_Expansion(self.key_rounds)
    def add_round_keys(self,M1,M2):
        return np.array(self.key_exp.xor(M1,M2)).reshape(4,4)
    def invshift(self):
        pass
    def invSubBytes(self):
        pass
    def invMixCols(self):
        pass     
    def Decryption(self,cypherText,key):
        #try:        
        if isinstance(cypherText,np.ndarray):
            matrix = cypherText 
        elif not self.functions.is_hex(cypherText):
            print("\n")
            print(f"cyphertext{cypherText}")
            val = self.functions.to_hex(cypherText)                          
            matrix = self.functions.hex_to_matrix(val)                  
        if isinstance(key,np.ndarray):
            matrix2 = key             
        elif not self.functions.is_hex(key):                        
            val2 = self.functions.to_hex(key)  
            print(type(val2))                                       
            matrix2 = self.functions.hex_to_matrix(val2)                                                                                                                            
        keys = self.key_exp.key_expansion(matrix2)              
        """except Exception as e:
            print(e)
            print('Decryption not completed yet defaulting to printing Encrypted text')
            return cypherText   """   