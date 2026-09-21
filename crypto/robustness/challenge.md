IND-CCA is all I'll ever need.

Now that you have successfully implemented a secure AEAD scheme, reflect on what the security guarantees AEAD actually provides.

Take a look at the server code: you never learn the secret key, and, by the definition IND-CCA security, you will never be able to forge new valid tokens... Or will you?