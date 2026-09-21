(a+b)(a-b) = a^2 - b^2
Damn, foiled again! I have fixed my parameters, implemented a faster key generation and used OAEP which is provably secure!

In this challenge certain aspects of the key generation algorithm, as well as the padding algorithm used have been fixed. See if there is another way of decrypting the flag!

The server again provides you with a encrypted_flag endpoint, which returns the encryption of your flag, N and e to you. You also get encrypt and decrypt endpoints, the latter of which is not implemented.

Here is an example of the potential interaction with the server:

{"command": "encrypted_flag"}
{"ctxt": "36...9f", "N": "c0..69", "e": "65537"}

{"command": "decrypt", "ciphertext": "a8..51"}
{"res": "Under construction"}

{"command": "encrypt", "plaintext": "68656c6c6f20776f726c6421"}
{"ctxt": "85...b9", "N": "c0..69", "e": "65537"}