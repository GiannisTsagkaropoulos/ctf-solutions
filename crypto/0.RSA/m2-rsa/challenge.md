Ah! I have encrypted the flag with state of the art 4096-bit RSA.

You are given a server that uses text-book RSA with a 4096-bit RSA modulus N.

The server provides the following commands:

The encrypt command takes some plaintext plaintext and encrypts it. It returns the resulting ciphertext, the server's public key ((N, e) where e = 3).
The encrypted_flag behaves like the encrypt command if it were given the flag as plaintext input, i.e., it encrypts the flag for you.
