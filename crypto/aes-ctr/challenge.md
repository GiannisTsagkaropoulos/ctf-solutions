The challenge description wasn't the following. I tried to reverse engineer the challenge description using my memory, AI and my comments from the writeups.

The server appends a secret flag to attacker-controlled plaintext and encrypts the result with a custom AES-CTR-like construction. For every request it chooses a fresh eight-byte nonce, increments a block counter from one, XORs each plaintext block with `nonce || counter`, encrypts that value with AES-ECB, and XORs the AES output with the plaintext block.

An encryption oracle is available through the `encrypt` command. Recover the appended flag from this oracle. The flag uses printable ASCII characters.