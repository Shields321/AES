import numpy as np
class Encryption:
    def __init__(self):
        pass    
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

    def hex_to_matrix(self,*args):
        """
        Convert a list of hexadecimal values into a 4x4 matrix.
    
        Parameters:
            *args: Variable length argument list of hexadecimal data to arrange into a 4x4 matrix. 
                Assumes 16 hexadecimal values are provided; otherwise, padding or error handling may be necessary.
                
        Returns:
            list: A 4x4 matrix (list of lists) containing the hexadecimal values for encryption purposes.
        """            
        pass    
    def xor(self, M1, M2):
        """Perform element-wise XOR operation on two 4x4 matrices.
        
        Args:
            M1 (np.array): The first 4x4 matrix for the XOR calculation.
            M2 (np.array): The second 4x4 matrix for the XOR calculation.
            
        Returns:
            np.array: A 4x4 matrix resulting from the XOR operation between M1 and M2.
        """
        #remember that ^ is used to xor values together
        pass
    
aes = Encryption()
val, val2 = aes.to_hex("This is the original Text", 1365)
print(val)
print(val2)
