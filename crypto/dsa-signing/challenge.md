The challenge description wasn't the following. I tried to reverse engineer the challenge description using my memory, AI and my comments from the writeups.

The server exposes a DSA public key and a verification endpoint. A message is accepted only if it begins with `who_is_it=its_britney&`, has a valid DSA signature, and passes a CMAC-based hash check. The DSA subgroup order is only 128 bits, and the hash is AES-CMAC under the all-zero key.

Forge a valid signature without the private key. Choose DSA nonce values to construct a signature and the corresponding target hash, then exploit CBC-MAC-style extension behavior in the fixed-key CMAC construction to append a block that makes the required message hash equal to that target.