# Helper function for Galois field multiplication
def galois_multiply(a,b,modulus=0x11B):    
    result = 0     
    for _ in range(8):
        if bin(b)[-1] == '1':
            result ^= a
        a = a*2
        if a >= 256:
            a ^= modulus
        b = b//2
    return result

# Perform the matrix multiplication in GF(2^8)
matrix1 = [
    [0x87, 0xf2, 0x4d, 0x97],
    [0x6e, 0x4c, 0x90, 0xec],
    [0x46, 0xe7, 0x4a, 0xc3],
    [0xa6, 0x8c, 0xd8, 0x95]
]

columns_matrix = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

# Result matrix initialization
result_matrix = []

# Matrix multiplication in GF(2^8)
for i in range(4):  # Iterate over columns of `matrix1`
    result_row = []
    for j in range(4):  # Iterate over rows of `columns_matrix`
        element = 0
        for k in range(4):  # Compute the dot product in GF(2^8)
            element ^= galois_multiply(matrix1[k][i], columns_matrix[j][k])
        result_row.append(element)
    result_matrix.append(result_row)

# Print the result in column-based format
for i in range(4):
    print([hex(result_matrix[j][i]) for j in range(4)])
         
