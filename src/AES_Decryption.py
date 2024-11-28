from SBOX import SBOX
from basic_functions import basic_functions
from Key_Expansion import Key_Expansion
import numpy as np
class Decryption:
    def __init__(self, AESMODE):
        self.sbox = SBOX()
        self.functions = basic_functions(mode="decrypt")
        self.keys = []
        self.key_rounds = {128: 10, 192: 12, 256: 14}[AESMODE]
        self.key_exp = Key_Expansion(self.key_rounds)

    def add_round_keys(self, M1, M2):
        return np.array(self.key_exp.xor(M1, M2)).reshape(4, 4)

    def invshift(self, matrix):
        result_matrix = []        
        for row in range(matrix.shape[0]):
            shift_val = row % matrix.shape[1]            
            shifted_row = np.roll(matrix[row], shift_val)            
            result_matrix.append(shifted_row)        
        result_matrix = np.array(result_matrix)        
        return result_matrix

    def invSubBytes(self, matrix):
        return self.sbox.inv_matrix_sub(matrix)

    def invMixCols(self, matrix):
        columns_matrix = [
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]
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

    def galois_multiply(self, a, b, modulus=0x11B):
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

    def Decryption(self, ciphertext: np.ndarray, key):
         
        if len(ciphertext.flatten()) > 16:
            decrpt = []
            for matrix in ciphertext:     
                decrpt.append(self.DecryptionProcess(matrix, key))
            state = self.functions.concatText(decrpt)
        elif len(ciphertext.flatten()) == 16:
            state = self.DecryptionProcess(ciphertext, key)
        else:
            raise ValueError("CipherText is not 16 bytes of length make sure its a correct encryption ciphertext")
        return state
    
    def DecryptionProcess(self, ciphertext: np.ndarray, key):
        matrix = ciphertext
        # Convert key to matrix if necessary
        if isinstance(key, np.ndarray):
            matrix2 = key
        elif not self.functions.is_hex(key):
            val2 = self.functions.to_hex(key)
            matrix2 = self.functions.hex_to_matrix(val2)

        # Expand the key
        self.keys = self.key_exp.key_expansion(matrix2)                   
        
        # Initial Add Round Key
        state = self.add_round_keys(matrix, self.keys[self.key_rounds])        
        
        # Perform rounds
        for round_num in range(self.key_rounds-1, 0, -1):  # Decrypting rounds in reverse order
            state = self.invshift(state)
            state = self.invSubBytes(state)   
            state = self.add_round_keys(state, self.keys[round_num])   
            if round_num != 0:      
                state = self.invMixCols(state)                        
        
        # Final round (no InvMixCols)
        state = self.invshift(state)
        state = self.invSubBytes(state)
        state = self.add_round_keys(state, self.keys[0])        
        
        return state
        

