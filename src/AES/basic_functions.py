import numpy as np
import hashlib as hash
class basic_functions():
    def __init__(self,mode = "encrypt") -> None:
        self.mode = mode
        self.hash = hash
        pass
    
    def is_hex(self,value):                                 
        if isinstance(value, str):
            # Try to interpret the string as a hexadecimal number
            try:
                int(value, 16)
                return True
            except ValueError:
                return False
        return False
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
            if len(args) == 1 and self.mode == 'decrypt':                                
                return segment         
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
        if len(matrix_data) < 16:
            vals.append(self.padding(matrix_data)) 
        return vals                                          
   
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
            count = 0
            matrix = [['00' for _ in range(4)] for _ in range(4)]                    
            for i in range(4):
                for j in range(4):                                      
                    matrix[j][i] = item[count]
                    count+=1  
            if len(args) == 1 and self.mode == 'decrypt':                                
                return np.array(matrix)                                    
            segments.append(np.array(matrix))            
        return segments
    
    def concatText(self ,*args):
        return np.concatenate(args,axis = 1)         

    def hash_key(self, key, AESMODE):   
        if AESMODE == 128:     
            key = self.hash.md5(key.encode()).digest()
        elif AESMODE == 192:
            key = self.hash.sha256(key.encode()).digest()   
            key = key[:24] 
            pass
        elif AESMODE == 256:
            key = self.hash.sha256(key.encode()).digest()            
        return bytearray(key)
                 
    def to_text(self ,*args):        
        matrixs = np.array(args)
        convertedText = []
        for matrix in matrixs:
            for row in matrix.T:
                for col in row:
                    convertedText.append(int(col,16))      
        text = ''.join(chr(char) for char in convertedText)
        return text