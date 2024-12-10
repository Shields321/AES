from AES.SBOX import SBOX
from AES.basic_functions import basic_functions
from AES.Key_Expansion import Key_Expansion
import numpy as np
class Decryption:
    def __init__(self, AESMODE):
        """
        Initialize the AES decryption class with the specified AES mode (key size).

        This constructor sets up the necessary components for AES decryption, including the S-box for the 
        SubBytes operation, the basic functions required for decryption, and the key schedule based on the 
        specified AES mode (key size). The number of rounds for AES decryption is determined based on the 
        AES mode (128, 192, or 256 bits).

        Parameters:
            AESMODE (int): The size of the AES encryption key in bits. Accepted values are 128, 192, or 256.
                            This value determines the number of rounds used for decryption.

        Attributes:
            sbox (SBOX): An instance of the S-box used for the SubBytes step in AES decryption.
            functions (basic_functions): An instance of the basic functions class initialized for decryption.
            keys (list): A list to store the round keys generated during key expansion.
            AESMODE (int): The key size (in bits) used for AES decryption (128, 192, or 256).
            key_rounds (int): The number of rounds for AES decryption, based on the key size.
            key_exp (Key_Expansion): An instance of the Key_Expansion class used for generating round keys.
        """
        self.sbox = SBOX()
        self.functions = basic_functions(mode="decrypt")
        self.keys = []
        self.AESMODE = AESMODE
        self.key_rounds = {128: 10, 192: 12, 256: 14}[self.AESMODE]
        self.key_exp = Key_Expansion(self.key_rounds)

    def add_round_keys(self, M1, M2):
        """
        Perform the AddRoundKey step in the AES Decryption process.

        This function takes two matrices, M1 and M2, representing the current state of the block and the 
        round key, respectively, and applies an XOR operation between them. The result is reshaped into 
        a 4x4 matrix, as required by the AES algorithm.

        Parameters:
            M1 (array-like): The current state of the block, represented as a 1D array to be XORed with the round key.
            M2 (array-like): The round key, also represented as a 1D array, to be XORed with the block state.
        
        Returns:
            np.ndarray: A 4x4 matrix representing the result of the XOR operation between M1 and M2.
        """
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
        """
        Perform multiplication in the Galois Field GF(2^8), used in AES for operations like MixColumns.

        This function multiplies two numbers (a and b) in the Galois Field GF(2^8), which is the finite field 
        used in AES encryption. The multiplication is done using the modulus value (default 0x11B for AES) to 
        ensure the result stays within the field's size. The function uses bitwise operations to simulate the 
        multiplication process in GF(2^8).

        Parameters:
            a (hex string or int): The first operand, represented as a hexadecimal string or an integer.
            b (int): The second operand, represented as an integer.
            modulus (int, optional): The modulus used for the field (default is 0x11B, which is the AES polynomial).

        Returns:
            int: The result of the Galois Field multiplication of a and b, as an integer.
        """  
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
        key = self.functions.hash_key(key,self.AESMODE)
        if len(ciphertext.flatten()) > 16:
            decrpt = []
            for matrix in ciphertext:     
                decrpt.append(self.DecryptionProcess(matrix, key))
            state = self.functions.concatText(decrpt)
            return self.functions.to_text(*state)
        elif len(ciphertext.flatten()) == 16:
            state = self.DecryptionProcess(ciphertext, key)
            return self.functions.to_text(state)
        else:
            raise ValueError("CipherText is not 16 bytes of length make sure its a correct encryption ciphertext")                
    
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
        

