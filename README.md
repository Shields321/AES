# AES Encryption Implementation

This project implements the **AES (Advanced Encryption Standard)** algorithm in Python, focusing on both encryption and decryption processes. The implementation ensures accuracy by adhering to reliable cryptographic principles and referencing trusted sources for key operations, such as key expansion and MixColumns transformations.

## Features

- Full implementation of AES encryption and decryption processes.
- Detailed breakdown of key expansion, MixColumns, SubBytes, ShiftRows, and other AES components.
- Validation of encryption results against trusted references to ensure correctness.
- Support for key sizes of 128, 192, and 256 bits.

## Components

### 1. AES Encryption
The AES encryption process involves multiple rounds of transformations, including SubBytes, ShiftRows, MixColumns, and AddRoundKey. Each round is performed with a round key derived from the original key via key expansion. This section covers the implementation of these operations.

### 2. AES Decryption
AES decryption is the reverse process of encryption, utilizing inverse operations. The decryption implementation follows the AES decryption algorithm, including inverse SubBytes, inverse ShiftRows, and inverse MixColumns, along with AddRoundKey operations.

### 3. Key Expansion
Key expansion generates a set of round keys from the original key. This process involves applying specific transformations to the key to produce keys used for each round of encryption and decryption. 

### 4. MixColumns
The MixColumns step is crucial for ensuring diffusion in AES encryption. The implementation of this transformation follows the Rijndael MixColumns algorithm, which operates in the Galois Field GF(2^8).

## References

### Encryption
The following resources provided essential information for the implementation of the AES encryption process:
- [Simplilearn: AES Encryption](https://www.simplilearn.com/tutorials/cryptography-tutorial/aes-encryption)

### AES Key Expansion
The key expansion process is integral to AES encryption and decryption. The following references were used to understand and implement this:
- [YouTube: AES Key Expansion (0RxLUf4fxs8)](https://www.youtube.com/watch?v=0RxLUf4fxs8)
- [Braincoke: The AES Key Schedule Explained](https://braincoke.fr/blog/2020/08/the-aes-key-schedule-explained/#aes-key-schedule)

### MixColumns
The MixColumns transformation provides diffusion by mixing the columns of the state matrix. These resources explain how this operation works:
- [Wikipedia: Rijndael MixColumns](https://en.wikipedia.org/wiki/Rijndael_MixColumns)
- [YouTube: MixColumns Explained (WPz4Kzz6vk4&t=377s)](https://www.youtube.com/watch?v=WPz4Kzz6vk4&t=377s)

### Decryption
AES decryption reverses the steps of encryption, and these references helped guide the implementation:
- [Braincoke: The AES Decryption Algorithm Explained](https://braincoke.fr/blog/2020/08/the-aes-decryption-algorithm-explained/#invsubbytes)
- [Wallarm: What is AES (Advanced Encryption Standard)?](https://www.wallarm.com/what/what-is-aes-advanced-encryption-standard)

### Hash Function
For the implementation of hash functions used in key handling:
- [Python Documentation: hashlib](https://docs.python.org/3/library/hashlib.html)
