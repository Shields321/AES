from SBOX import SBOX
from Key_Expansion import Key_Expansion
from basic_functions import basic_functions
import numpy as np
class Encryption:    
    def __init__(self,AESMODE=128):
        """
        Initialize the Encryption class with the provided key size, S-box, and default round settings.
        
        Parameters:
            AESMODE (int): The size of the encryption key in bits. Supported values are 128, 192, or 256.
                            Determines the number of rounds used for encryption.
        
        Attributes:
            sbox (SBOX): Substitution box used for the AES encryption.
            words (list): Stores the key schedule's words.
            keys (list): Contains the round keys generated during key expansion.
            key_rounds (int): Number of rounds for AES encryption based on the key size.
        """
        self.sbox = SBOX()  
        self.functions = basic_functions()           
        self.words = [] 
        self.keys = []
        self.key_rounds = {128:10, 192:12, 256:14}[AESMODE] 
        self.KeyGen = Key_Expansion(key_size=self.key_rounds)                          
                        
    def add_round_keys(self,M1,M2):
        return np.array(self.KeyGen.xor(M1,M2)).reshape(4,4)
    def shift_rows(self, matrix):
        result_matrix = []
        for row in range(matrix.shape[0]):
            shift_val = row % matrix.shape[1]  
            shifted_row = np.roll(matrix[row], -shift_val)
            result_matrix.append(shifted_row)
        result_matrix = np.array(result_matrix)
        return result_matrix         
    def mix_cols(self,matrix):
        columns_matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]    
        result_matrix = []            
        # Matrix multiplication in GF(2^8)
        for i in range(4):  # Iterate over columns of `matrix1`
            result_row = []
            for j in range(4):  # Iterate over rows of `columns_matrix`
                element = 0
                for k in range(4):  # Compute the dot product in GF(2^8)
                    element ^= self.galois_multiply(matrix[k][i], columns_matrix[j][k])
                result_row.append(hex(element))
            result_matrix.append(result_row)                                 
        return np.array(result_matrix).T
    def galois_multiply(self,a,b,modulus=0x11B):    
        result = 0         
        a = int(a,16)
        for _ in range(8): # 8 round for the GF(2^8)
            if bin(b)[-1] == '1': #check the least significant bit of b and see if its 1
                result ^= a
            a = a*2 # right shift
            if a >= 256:
                a ^= modulus
            b = b//2 #left shift
        return result                                        
    def Encryption(self,plaintext,key):
        val, val2 = self.functions.to_hex(plaintext, key)
        matrix, matrix2= self.functions.hex_to_matrix(val,val2)        
        keys = self.KeyGen.key_expansion(matrix2)                               
        # Initial key round addition
        matrix = self.add_round_keys(matrix, keys[0])  # First round key addition        
        # Loop through all the rounds
        for i in range(1, self.key_rounds):  
            subMatrix = self.sbox.matrix_Sub(matrix)  # Apply SubBytes                        
            shift_rows = self.shift_rows(subMatrix)  # Apply ShiftRows                        
            if i != self.key_rounds:  # Only apply MixColumns in intermediate rounds
                mix_col = self.mix_cols(shift_rows)  # Apply MixColumns                
            else:                
                mix_col = shift_rows  # Skip MixColumns in the final round                            
            # Add the round key at the end of each round (except for the final round)
            matrix = self.add_round_keys(mix_col, keys[i])  # Use the i-th round key from expanded key schedule            
        # Final round (no MixColumns)
        subMatrix = self.sbox.matrix_Sub(matrix)  # Apply SubBytes
        shift_rows = self.shift_rows(subMatrix)  # Apply ShiftRows
        cipher_text = self.add_round_keys(shift_rows, keys[self.key_rounds])  # Final AddRoundKey

        print('final ciphertext')
        print(cipher_text)                                                                                        