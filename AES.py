from SBOX import SBOX
from Key_Expansion import Key_Expansion
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
        self.KeyGen = Key_Expansion()       
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
                segment = [hex(ord(char)).upper() for char in item]  # Convert each character to hex
            elif isinstance(item, int):  # If the input is an integer
                segment = [hex(item).upper()]  # Convert integer to hex
            elif isinstance(item, bytes):  # If the input is bytes
                segment = [hex(byte).upper() for byte in item]  # Convert each byte to hex
            elif isinstance(item, bytearray):  # If the input is bytearray
                segment = [hex(byte).upper() for byte in item]  # Convert each byte to hex
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
                        
    def round_keys(self,M1,M2):
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
                                  
        
        return matrix
    def galois_field(self,a,b):
        
        pass      
    def Encryption(self,plaintext,key):
        val, val2 = aes.to_hex(plaintext, key)
        matrix, matrix2= aes.hex_to_matrix(val,val2)        
        keys = self.KeyGen.key_expansion(matrix2)
        #for i in range(self.key_rounds):
        key_round = self.round_keys(matrix,keys[0]) 
        subMatrix = self.sbox.matrix_Sub(key_round) 
        shift_rows = self.shift_rows(subMatrix)         
        mix_col = self.mix_cols(shift_rows) 
        matrix = mix_col 
                                                                 
               
aes = Encryption()
aes.Encryption("Two One Nine Two","Thats my Kung Fu")



