from SBOX import SBOX
import numpy as np
class Encryption:    
    def __init__(self,key_size=128):
        """
        Initialize the Encryption class with the provided key size, S-box, and default round settings.
        
        Parameters:
            key_size (int): The size of the encryption key in bits. Supported values are 128, 192, or 256.
                            Determines the number of rounds used for encryption.
        
        Attributes:
            sbox (SBOX): Substitution box used for the AES encryption.
            words (list): Stores the key schedule's words.
            keys (list): Contains the round keys generated during key expansion.
            key_rounds (int): Number of rounds for AES encryption based on the key size.
        """
        self.sbox = SBOX()
        self.words = [] 
        self.keys = []
        self.key_rounds = {128:10, 192:12, 256:14}[key_size] 
        self.keys.append("to be added")       
    def to_hex(self ,*args):
        """Convert data into hexadecimal format.
        
        Parameters:
            *args: Variable length argument list of data (string, integer, bytes, bytearray) to convert to hexadecimal.
        
        Returns:
            list: A list of hexadecimal representations for each input value.
        
        Raises:
            ValueError: If the data type is not string, integer, bytes, or bytearray.
        """        
        segments = []
        for item in args:
            if isinstance(item, str):  # If the input is a string
                segment = [hex(ord(char)) for char in item]  # Convert each character to hex
            elif isinstance(item, int):  # If the input is an integer
                segment = [hex(item)]  # Convert integer to hex
            elif isinstance(item, bytes):  # If the input is bytes
                segment = [hex(byte) for byte in item]  # Convert each byte to hex
            elif isinstance(item, bytearray):  # If the input is bytearray
                segment = [hex(byte) for byte in item]  # Convert each byte to hex
            else:
                raise ValueError("Unsupported data type. Expected string, integer, bytes, or bytearray.")            
            segments.append(segment)  # Add each segment to the list of segments        
        return segments
    def padding(self,hex_data):
        """Pads a list of hexadecimal data to 16 bytes if required.
        
        Parameters:
            hex_data (list): List of hexadecimal data strings.
        
        Returns:
            list: The input list padded to a length of 16 hexadecimal strings, using '0x00' as padding.
        """
        pad = 16-len(hex_data)
        for _ in range(pad):
            hex_data.append('0x00')
        return hex_data
        
    def overflow(self,data):
        """
        Splits a list of hexadecimal data into 16-byte chunks and pads the final chunk if necessary.
        
        This function divides the input `data` into multiple 16-byte segments, which are required for AES encryption.
        Each segment is stored in `vals`. If the last chunk contains fewer than 16 bytes, it is padded to a length 
        of 16 bytes using the `padding` function, which appends '0x00' as needed.
        
        Parameters:
            data (list): A list of hexadecimal values, each represented as a string (e.g., '0x54', '0x68'). 
                        The list can be of any length, and the function will split it into 16-byte segments.
                        
        Returns:
            list: A list of 16-byte segments, where each segment is a list of 16 hexadecimal strings. 
                The last segment is padded with '0x00' if its length is less than 16.
                
        Example:
            >>> data = ['0x54', '0x68', '0x69', '0x73', '0x20', '0x69', '0x73', '0x20',
                        '0x74', '0x68', '0x65', '0x20', '0x54', '0x65', '0x78', '0x74', 
                        '0x00', '0x01']
        >>> overflow(data) = [['0x54', '0x68', '0x69', '0x73', '0x20', '0x69', '0x73', '0x20',
        '0x74', '0x68', '0x65', '0x20', '0x54', '0x65', '0x78', '0x74'],
        ['0x00', '0x01', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00',
        '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00']]
        """        
        vals = []
        matrix_data = []
        for byte in data:
            matrix_data.append(byte)
            if len(matrix_data) == 16:
                vals.append(matrix_data)
                matrix_data = [] 
        if matrix_data:
            vals.append(self.padding(matrix_data))                                           
                    
        
    def hex_to_matrix(self,*args):
        """
        Convert a list of hexadecimal values into a 4x4 matrix.
    
        Parameters:
            *args: Variable length argument list of hexadecimal data to arrange into a 4x4 matrix. 
                Assumes 16 hexadecimal values are provided; otherwise, padding or error handling may be necessary.
                
        Returns:
            list: A 4x4 matrix (list of lists) containing the hexadecimal values for encryption purposes.
        """                     
        segments = []              
        for item in args:  
            #make it so that the padding and overflow still get converted to a matrix form after           
            if len(item) < 16:                
                self.padding(item)
            elif len(item) > 16:                 
                self.overflow(item)
            count = 0
            matrix = [['00' for _ in range(4)] for _ in range(4)]                    
            for i in range(4):
                for j in range(4):
                    
                    matrix[j][i] = item[count]
                    count+=1
            segments.append(np.array(matrix))
        return segments    
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
            new_word[i] = self.sbox.list_Sub(new_word[i])                                                                                  
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
            Wi = self.xor(self.words[i],result[i-1],mode='flat')
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
        round = 0
        
        # Start with initial key
        self.keys.append(self.words[:4])  # W0, W1, W2, W3 as the first round key
        
        # Generate remaining keys for all rounds
        for _ in range(self.key_rounds):
            # Generate the next 4 words based on the last 4 words in self.words
            new_words = self.key_generation(self.words[-4:], round)                       
            self.words.extend(new_words)  # Add the new words to the list
            self.keys.append(new_words)   # Add the new round key to keys
            round += 1
        
        return self.keys             
                                                            
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
                result.append(f'{val1 ^ val2:02X}')    
        elif mode == 'flat':  
            for i in range(4):  
                val1 = int(M1[i],16)
                val2 = int(M2[i],16)          
                result.append(f'{val1 ^ val2:02X}')          
        elif mode == 'matrix':                            
            for row in range(len(M1)):            
                for col in range(len(M2)):
                    val1 = int(M1[row][col],16)
                    val2 = int(M2[row][col],16)                       
                    result.append(f'{val1 ^ val2:02X}')
        else:
            raise ValueError("Invalid mode. Expected 'Rcon', 'flat', or 'Matrix'.")
        return result                 
aes = Encryption()
val, val2 = aes.to_hex("Two One Nine Two", "Thats my Kung Fu")
matrix, matrix2= aes.hex_to_matrix(val,val2)
keys = aes.key_expansion(matrix2)

for key in keys:
    print(key)