Presenting my novel key generation algorithm!

In this challenge, you are given a server that implements my custom key generation algorithm. My algorithm manually seeds the random generators used to generate p and q. The seeding is carefully engineered to ensure that for any two private keys (p,q) and (p',q'), p and p' are generated from the same seed if and only if q and q' will be generated from the same seed.

The server provides the following commands:

The generate command requires no inputs. It generates a new key pair using the custom key generation algorithm. It returns the public key consisting of N and e. Additionally, each key is associated with an index returned to you in the key_index field.
The encrypt command takes a key index as input index. It encrypts the flag using the key associated with the provided index and returns it in the encrypted_flag field.
Note that this server uses pycryptodome's implementation of RSA. You can create a cipher object (used for encryption and decryption) like so:

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.construct((N, e, d))
cipher = PKCS1_OAEP.new(key)