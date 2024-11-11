from SBOX import SBOX
import numpy as np
class Encryption:    
    def __init__(self,key_size=128):
        self.sbox = SBOX()
        self.words = [] 
        self.keys = []
        self.key_rounds = {128:10, 192:12, 256:14}[key_size]        
    def to_hex(self ,*args):
        """Convert data into hexadecimal values.
        
        Parameters:
            *args: Variable length argument list of data to convert to hexadecimal. 
                Accepts integers, strings, bytes, bytearray.
                
        Returns:
            list: A list of hexadecimal strings representing the input values in hex form.
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
        """filling the array of hexadecimal data to be 16 bytes
        
            Parameters:
                hex_data: Variable length argument list of hexadecimal data to pad to 32 bytes.                     
            
            Returns:
                list: A list of hexadecimal strings representing the input values in hex form.
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
            >>> overflow(data)
            [['0x54', '0x68', '0x69', '0x73', '0x20', '0x69', '0x73', '0x20',
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
        print(vals)                                    
                    
        
    def hex_to_matrix(self,*args,xor=False):
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
                    if xor:
                        matrix[i][j] = item[count]
                    else:
                        matrix[j][i] = item[count]
                    count+=1
            segments.append(np.array(matrix))
        return segments    
    def generation_factor(self,W):
        # Rcon values
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
        ]  
        new_word = []
        print(W)
        for i in range(len(W),0,-1):
            new_word.append(W[i-1])
        print(new_word)
            
        
    def key_generation(self,key_matrix):
        """used to do the key generation for the round keys for each round.
        
        Args:
            matrix2 (list): key.
            
        Returns:
            list: a list of a list of keys in hexadecimal format 
        """                                                
        for i in range(len(key_matrix)):   
            word = []            
            for row in range(len(key_matrix)):                            
                word.append(key_matrix[row][i])                       
            self.words.append(word) 
        self.generation_factor(self.words[len(key_matrix)-1])                                                               
    def xor(self, M1, M2):
        """Perform element-wise XOR operation on two 4x4 matrices.
        
        Args:
            M1 (np.array): The first 4x4 matrix for the XOR calculation.
            M2 (np.array): The second 4x4 matrix for the XOR calculation.
            
        Returns:
            np.array: A 4x4 matrix resulting from the XOR operation between M1 and M2.
        """
        #remember that ^ is used to xor values together
        result = []
        for row in range(len(M1)):            
            for col in range(len(M2)):
                val1 = int(M1[row][col],16)
                val2 = int(M2[row][col],16)                       
                result.append(f'{val1 ^ val2:02X}')
        print(self.hex_to_matrix(result,xor=True))
                
    
aes = Encryption()
val, val2 = aes.to_hex("Two One Nine Two", "Thats my Kung Fu")

matrix, matrix2= aes.hex_to_matrix(val,val2)
aes.key_generation(matrix2)


