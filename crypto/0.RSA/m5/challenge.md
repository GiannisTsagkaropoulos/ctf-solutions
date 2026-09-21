I trust my RSA so much that I'm going to make you change the public exponent as well! After all, public means that everyone should be able to do what they wish, right?

In this challenge, you will interacting with a server that lets you choose your own value for e in the encryption of the flag value.

The server will sample a normal RSA key, according to textbook RSA, and you can query the modulus N using the pub_key parameters. However, when the encrypt handler is called, you have to provide the value for e, i.e. the public exponent, which you can choose freely with some restrictions. Namely, it may not be equal to 1 , -1, and has to be coprime to phi (remember, phi is equal to (p-1) * (q-1) for the sampled large primes p, q). If this conditions on your chosen e are met, the server will return the encryption of the flag string to you. Find a way to recover the plaintext!

Again, here are some examples of interaction with the server

{"command": "pub_key"}
{"message": "When encrypting, remember to give me a public exponent", "N": "c3...7b"}

{"command": "encrypt", "e": 315936081561346625673859763307800699647}
{"ciphertext": "6a8b"}
Please consider that your attack may not succeed every time and potentially implement your attack script in a way to retry certain actions, gracefully handling certain errors.