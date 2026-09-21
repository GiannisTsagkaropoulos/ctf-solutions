This challenge will help you implement some building blocks required for a full padding oracle attack.

In a padding oracle attack, the adversary must have the capability to distinguish ciphertexts that map to a correctly padded plaintext from ciphertexts that do not map to a correctly padded plaintext.

You will interact with a server (see server.py). The decrypt command expect a ciphertext encrypted with AES-128-CBC under a key unknown to you, tries to decrypt it, and responds with a message encrypted under the same key (possibly, an error message!). After any number of encrypted commands, you can send a special command, guess, which allows you to guess whether the encrypted command you last sent was correctly padded or not.

Try to send some encrypted commands and observe the encrypted responses. Note that encryption and decryption use PKCS#7 padding.

Here is an example interaction with the server:

```python
{"command": "decrypt", "ciphertext": "c0e70a1a2d9ad0bc0536c8b5f993fd3a9bd5020eabfb2bb093eea4b64bed4707"}
{"res": "Invalid parameters: 8c215c379c34006f7fd67709ff5a98e86514fd55b585e2fab3ce03bb98bdb94d12f7d3e60306f881b859071ba06d5d38d6bcc969928fba16e15cc4ca0d4db781"}
{"command": "guess", "guess": true}
{"res": "You won round 1/300!"}
```
You win if you show a significant advantage in this guessing game -- you can ask for the flag using the flag command after 300 correct consecutive guesses.