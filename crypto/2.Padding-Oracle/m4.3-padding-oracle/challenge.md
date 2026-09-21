In this challenge, you will interact with an extremely simplified secure shell server (see server.py).

The server takes an encrypted_command, decrypts it with its secret key, and executes some supported commands. Then sends back an encrypted reply.

The designer of this server thought that IND-CPA security of AES-CBC would be enough to assure that no information is leaked to an attacker trying to interact with this server! Can you still recover the flag?