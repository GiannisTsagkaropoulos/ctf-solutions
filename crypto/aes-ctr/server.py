from boilerplate import CommandServer, on_command

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import secrets

BLOCK_SIZE = 16

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

class AESCTRDoubleXOR:
    def __init__(self, key, nonce):
        assert len(key) == 16, "Key must be 16 bytes long."
        assert len(nonce) == 8, "Nonce must be 8 bytes long."
        self.key = key
        self.nonce = nonce
        self.counter = 0

    def encrypt(self, plaintext):
        padded_ptxt = pad(plaintext, BLOCK_SIZE)
        ptxt_blocks = [padded_ptxt[i:i+BLOCK_SIZE] for i in range(0, len(padded_ptxt), BLOCK_SIZE)]

        out = []

        cipher = AES.new(self.key, AES.MODE_ECB)

        for ptxt_block in ptxt_blocks:
            self.counter += 1
            print("\nblock: ", ptxt_block)
            print("counter: ", self.counter)
            counter_block = self.nonce + self.counter.to_bytes(8, 'big')
            input_block = xor(ptxt_block, counter_block)
            keystream_block = cipher.encrypt(input_block)
            ciphertext_block = xor(ptxt_block, keystream_block)
            print("ciphertext_block", ciphertext_block)    
            out.append(ciphertext_block)

        return b''.join(out)

    def decrypt(self, ciphertext):
        raise NotImplementedError("Decryption is not implemented for AES-CTR Double-XOR mode.")


class SpielbergServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.k = secrets.token_bytes(16)
        super().__init__(*args, **kwargs)

    @on_command("encrypt")
    def handle_challenge(self, msg):
        try:
            m = bytes.fromhex(msg["ptxt"])
            print("\nMessage: ", m)
            cipher = AESCTRDoubleXOR(self.k, secrets.token_bytes(8))
            ctxt = cipher.encrypt(m + self.flag.encode())
            self.send_message({"ctxt": ctxt.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

if __name__ == "__main__":
    flag = "flag{abcd12_213423qowweqr2341qa1asd}"
    SpielbergServer.start_server("0.0.0.0", 50400, flag=flag)
