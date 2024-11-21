from SBOX import SBOX
import numpy as np
class Key_Expansion:
    def __init__(self, key_size):
        self.sbox = SBOX()        
        self.words = []
        self.keys = []
        self.key_rounds = key_size
    def generation_factor(self,W,round):
        """
        Generates a new word for the key schedule based on the AES key expansion algorithm.
        
        Parameters:
            W (list): A word from the key schedule.
            round (int): Current round number to access the corresponding Rcon value.
        
        Returns:
            list: New word generated for the key schedule.
        """
        # Rcon values its just start from 1 and multiply by 2 each time               
        Rcon = [
            [0x01, 0x00, 0x00, 0x00],
            [0x02, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00],
            [0x08, 0x00, 0x00, 0x00],
            [0x10, 0x00, 0x00, 0x00],
            [0x20, 0x00, 0x00, 0x00],
            [0x40, 0x00, 0x00, 0x00],
            [0x80, 0x00, 0x00, 0x00],
            [0x1B, 0x00, 0x00, 0x00],
            [0x36, 0x00, 0x00, 0x00],
            [0x6C, 0x00, 0x00, 0x00],
            [0xD8, 0x00, 0x00, 0x00],
            [0xAB, 0x00, 0x00, 0x00],
            [0x4D, 0x00, 0x00, 0x00],
            [0x9A, 0x00, 0x00, 0x00]
        ]        
        new_word = [W[1],W[2],W[3],W[0]]        
                                                     
        for i in range(len(new_word)):
            new_word[i] = self.sbox.byte_Sub(new_word[i])                                                                            
        return self.xor(Rcon[round],new_word,mode='Rcon')
                    
    def key_generation(self,word,round):  
        """
        Generates four words for the current round key based on the previous round's words.
        
        Parameters:
            previous_words (list): List of the four words from the previous round.
            round (int): Current round number for generating the appropriate round key.
        
        Returns:
            list: A list containing four words (lists of bytes) for the current round key.
        """                        
        result = []        
        W4 = self.xor(word[0],self.generation_factor(word[3],round),mode='flat')
        result.append(W4) 
         
        for i in range(1,4):                        
            Wi = self.xor(word[i],result[i-1],mode='flat')            
            result.append(Wi)                               
        return result
                 
    def key_generation_setup(self,key_matrix): 
        """
        Initializes the first four words (W0, W1, W2, W3) from the initial key matrix.
        
        Parameters:
            key_matrix (list): A 4x4 matrix of hexadecimal values representing the initial key.
        """                                         
        for i in range(len(key_matrix)):   
            word = []            
            for row in range(len(key_matrix)):                            
                word.append(key_matrix[row][i])                       
            self.words.append(word) 
            
    def key_expansion(self,key_matrix,round=0):
        """
        Generates the full round keys for AES encryption.
        
        Parameters:
            key_matrix (list): A 4x4 matrix of hexadecimal values representing the initial key.
        
        Returns:
            list: List of round keys for AES encryption.
        """
        self.key_generation_setup(key_matrix)
        
        # Start with initial key
        self.keys.append(self.words[:4])  # W0, W1, W2, W3 as the first round key
        
        # Generate remaining keys for all rounds
        for _ in range(self.key_rounds):
            # Generate the next 4 words based on the last 4 words in self.words
            new_words = self.key_generation(self.words[-4:], round)                       
            self.words.extend(new_words)  # Add the new words to the list
            self.keys.append(new_words)   # Add the new round key to keys
            round += 1        
        return self.inverse_matrix(np.array(self.keys))  
    
    def inverse_matrix(self,matrix_keys):
        """
        Transposes each key in the list of matrices `matrix_keys` and returns the transposed matrices.
        
        Parameters:
            matrix_keys (list of np.array): A list of 2D numpy arrays representing the keys. Each matrix is transposed.
            
        Returns:
            list: A list of transposed matrices (np.array).
        """
        k = []
        for key in matrix_keys:
            k.append(key.T)
        return k   
            
    def xor(self, M1, M2,mode ='matrix'):
        """Perform element-wise XOR operation between two matrices or lists.
    
        Parameters:
            M1 (list or np.array): The first matrix or list for XOR.
            M2 (list or np.array): The second matrix or list for XOR.
            mode (str): Specifies the type of XOR operation ('Rcon', 'flat', 'matrix').
            
        Returns:
            list: A list of results from the XOR operation.
        """
        result = [] 
        if mode =='Rcon':            
            for i in range(4):  
                val1 = M1[i]
                val2 = int(M2[i],16)          
                result.append(hex(val1 ^ val2).upper())   
        elif mode == 'flat':  
            for i in range(4):  
                val1 = int(M1[i],16)
                val2 = int(M2[i],16)          
                result.append(hex(val1 ^ val2).upper())          
        elif mode == 'matrix':                            
            for row in range(len(M1)):            
                for col in range(len(M2)):
                    val1 = int(M1[row][col],16)
                    val2 = int(M2[row][col],16)                       
                    result.append(hex(val1 ^ val2).upper())            
        else:
            raise ValueError("Invalid mode. Expected 'Rcon', 'flat', or 'Matrix'.")
        return result