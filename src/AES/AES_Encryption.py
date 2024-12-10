from AES.SBOX import SBOX
from AES.Key_Expansion import Key_Expansion
from AES.basic_functions import basic_functions
import numpy as np
class Encryption:    
    def __init__(self,AESMODE=128):
        """
        Initialize the AES Encryption class with the specified encryption key size and related parameters.
        
        This constructor sets up the key size, initializes the substitution box (S-box), prepares the 
        key schedule, and determines the number of rounds used in AES encryption based on the key size.
        
        Parameters:
            AESMODE (int): The size of the encryption key in bits. Accepted values are 128, 192, or 256. 
                        This determines the number of rounds used in the encryption process.
        
        Attributes:
            sbox (SBOX): The substitution box used for performing the SubBytes step in AES encryption.
            functions (basic_functions): A collection of basic AES functions used throughout the encryption process.
            words (list): Stores the words from the expanded key schedule, which is used during encryption rounds.
            keys (list): Contains the round keys generated from the key schedule, used in each round of AES encryption.
            AESMODE (int): The key size in bits (128, 192, or 256) that defines the encryption strength and rounds.
            key_rounds (int): The number of rounds for AES encryption, determined by the AES key size. 
                            - 128-bit key: 10 rounds
                            - 192-bit key: 12 rounds
                            - 256-bit key: 14 rounds
            KeyGen (Key_Expansion): Instance of the Key_Expansion class used to generate the key schedule and round keys.
        """
        self.sbox = SBOX()  
        self.functions = basic_functions()           
        self.words = [] 
        self.keys = []
        self.AESMODE = AESMODE
        self.key_rounds = {128:10, 192:12, 256:14}[self.AESMODE] 
        self.KeyGen = Key_Expansion(key_size=self.key_rounds)                          
                        
    def add_round_keys(self,M1,M2):
        """
        Perform the AddRoundKey step in the AES encryption process.

        This function takes two matrices, M1 and M2, representing the current state of the block and the 
        round key, respectively, and applies an XOR operation between them. The result is reshaped into 
        a 4x4 matrix, as required by the AES algorithm.

        Parameters:
            M1 (array-like): The current state of the block, represented as a 1D array to be XORed with the round key.
            M2 (array-like): The round key, also represented as a 1D array, to be XORed with the block state.
        
        Returns:
            np.ndarray: A 4x4 matrix representing the result of the XOR operation between M1 and M2.
        """
        return np.array(self.KeyGen.xor(M1,M2)).reshape(4,4)
    
    def shift_rows(self, matrix):
        """
        Perform the ShiftRows step in the AES encryption process.

        This function takes a 4x4 matrix (state) and shifts the rows of the matrix according to the AES specification.
        Each row is shifted left by a number of positions that corresponds to its row index.

        Parameters:
            matrix (np.ndarray): A 4x4 matrix representing the current state of the AES block. The matrix should
                                have the shape (4, 4), where each row is a 1D array representing a block of data.

        Returns:
            np.ndarray: A 4x4 matrix where each row has been cyclically shifted to the left by an amount
                        corresponding to its row index.
        """
        result_matrix = []
        for row in range(matrix.shape[0]):
            shift_val = row % matrix.shape[1]  
            shifted_row = np.roll(matrix[row], -shift_val)
            result_matrix.append(shifted_row)
        result_matrix = np.array(result_matrix)
        return result_matrix 
            
    def mix_cols(self,matrix):
        """
        Perform the MixColumns step in the AES encryption process.

        This function takes a 4x4 matrix (state) and applies the MixColumns transformation, which is a linear 
        transformation that mixes the data in each column of the matrix. The transformation is performed by 
        multiplying the state matrix with a fixed constant matrix in GF(2^8) (the Galois Field), ensuring diffusion 
        of the data.

        Parameters:
            matrix (np.ndarray): A 4x4 matrix representing the current state of the AES block. Each element is a byte.

        Returns:
            np.ndarray: A 4x4 matrix where each column has been mixed based on the MixColumns transformation.
                        The result is a new matrix in which the columns have been diffused.
        """
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
                                       
    def Encryption(self,plaintext,key):  
        """
        Encrypt the given plaintext using the AES encryption algorithm.

        This function applies the AES encryption process to the provided plaintext using the specified key.
        It first hashes the key based on the AES mode (128, 192, or 256 bits) and converts the plaintext 
        into a suitable format for encryption. Depending on the length of the plaintext, it either encrypts 
        it directly, applies padding for short texts, or handles overflow for long texts by dividing the 
        plaintext into blocks.

        Parameters:
            plaintext (str or bytes): The plaintext to be encrypted, which will be processed into a 16-byte format.
            key (str or bytes): The encryption key to be used in AES, which is hashed based on the AES mode.

        Returns:
            str or bytes: The resulting ciphertext, either as a concatenated string or in block form, depending 
                        on the length of the input plaintext.
        """      
        key = self.functions.hash_key(key,self.AESMODE)
        val, val2 = self.functions.to_hex(plaintext, key)
        if len(val) == 16:
            cipher_text = self.EncrptionProcess(val, val2)
        elif len(val) < 16:
            val = self.functions.padding(val)
            cipher_text = self.EncrptionProcess(val, val2)
        elif len(val) > 16:
            val = self.functions.overflow(val)
            cipher = []        
            for matrix in val:
                cipher.append(self.EncrptionProcess(matrix, val2))
            cipher_text = self.functions.concatText(cipher)
        return cipher_text
             
    def EncrptionProcess(self,plaintext,key):   
        """
        Perform the AES encryption process on the given plaintext using the specified key.

        This function implements the core AES encryption process, which involves multiple rounds of 
        transformations (SubBytes, ShiftRows, MixColumns, and AddRoundKey) on the plaintext. The key 
        schedule is generated using the provided key, and the encryption proceeds with an initial round key 
        addition, followed by a series of intermediate rounds, and a final round without MixColumns.

        Parameters:
            plaintext (str or bytes): The plaintext to be encrypted, typically a 16-byte block.
            key (str or bytes): The encryption key used for key expansion, typically a 16, 24, or 32-byte key.

        Returns:
            np.ndarray: The resulting ciphertext after all AES rounds, as a 4x4 matrix of bytes.
        """
        matrix, matrix2= self.functions.hex_to_matrix(plaintext,key)            
        keys = self.KeyGen.key_expansion(matrix2)                                      
        # Initial key round addition
        state = self.add_round_keys(matrix, keys[0])  # First round key addition                        
        # Loop through all the rounds
        for i in range(1, self.key_rounds):  
            state = self.sbox.matrix_Sub(state)  # Apply SubBytes                        
            state = self.shift_rows(state)  # Apply ShiftRows                        
            if i != self.key_rounds:  # Only apply MixColumns in intermediate rounds
                state = self.mix_cols(state)  # Apply MixColumns                                                       
            # Add the round key at the end of each round (except for the final round)
            state = self.add_round_keys(state, keys[i])  # Use the i-th round key from expanded key schedule                        
        # Final round (no MixColumns)
        state = self.sbox.matrix_Sub(state)  # Apply SubBytes
        state = self.shift_rows(state)  # Apply ShiftRows
        cipher_text = self.add_round_keys(state, keys[self.key_rounds])  # Final AddRoundKey
           
        return cipher_text                                                                       