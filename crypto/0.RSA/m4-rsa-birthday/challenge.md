I'm organizing my birthday party! Can you help me send out all the invites?

In the server folder you will find a file called phonebook.py. It lists the friends that I want to invite to my birthday party. For each person I have also given you their RSA public key (N, e).

My server provides an invite command. This command expects one of my friends passed in the invitee field and encrypts the invitation using the friend's public key from the phonebook. The server then responds with the ciphertext.

Your job is to decrypt the invitation as it contains the flag.