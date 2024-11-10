class AES:
    def __init__(self):
        pass
    def to_hex(self, *args):
        """Convert data into hexadecimal values.
        
        Parameters:
            *args: Variable length argument list of data to convert to hexadecimal. 
                Accepts integers, strings, or other data types compatible with hex conversion.
                
        Returns:
            list: A list of hexadecimal strings representing the input values in hex form.
        """
        pass

    def hex_to_matrix(self,*args):
        """Convert a list of hexadecimal values into a 4x4 matrix.
    
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
        pass