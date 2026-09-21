import secrets
from boilerplate import CommandServer, on_command

from Crypto.Cipher import AES
from Crypto.Random.random import shuffle
from Crypto.Util.Padding import pad, unpad


BLOCK_SIZE = 16
MAX_BLOCKS = 32
MAX_BYTES = BLOCK_SIZE * MAX_BLOCKS
NONCE_SIZE = BLOCK_SIZE // 2
TOKEN_SIZE = BLOCK_SIZE
MAX_QUERIES = 50_000

def split_in_blocks(arr, block_size):
    blocks = [arr[i:i+block_size] for i in range(0, len(arr), block_size)]
    return blocks


class Shuffler:
    def __init__(self, n: int):
        self.n = n
        self.mapping = list(range(n))
        shuffle(self.mapping)
        self.inv_mapping = [0] * n
        for i, x in enumerate(self.mapping):
            self.inv_mapping[x] = i 

    def __call__(self, data: bytes) -> bytes:
        if len(data) != self.n:
            raise ValueError("incorrect input size")
        return bytes(data[self.mapping[i]] for i in range(self.n))

    def inv(self, data: bytes) -> bytes:
        if len(data) != self.n:
            raise ValueError("incorrect input size")
        return bytes(data[self.inv_mapping[i]] for i in range(self.n))


class ShuffledEncryptionServer(CommandServer):

    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.token = secrets.token_bytes(TOKEN_SIZE)
        print("self.token", self.token)
        self.key = secrets.token_bytes(16)
        self.perms = [Shuffler(i * BLOCK_SIZE) for i in range(MAX_BLOCKS + 1)]
        self.query_count = 0

        super().__init__(*args, **kwargs)

    def encrypt(self, msg: bytes) -> tuple[bytes, bytes]:
        ptxt = pad(msg, BLOCK_SIZE)
        if len(ptxt) > MAX_BYTES:
            raise ValueError("plaintext too long")

        perm = self.perms[len(ptxt) // BLOCK_SIZE]

        cipher = AES.new(self.key, AES.MODE_CTR)
        ctxt = perm(cipher.encrypt(ptxt))

        return bytes(cipher.nonce), ctxt

    def decrypt(self, nonce: bytes, ctxt: bytes) -> bytes:
        
        if len(nonce) != NONCE_SIZE:
            raise ValueError("incorrect nonce length")
        if (not (BLOCK_SIZE <= len(ctxt) <= MAX_BYTES)) or len(ctxt) % BLOCK_SIZE != 0:
            raise ValueError("incorrect ciphertext length")

        perm = self.perms[len(ctxt) // BLOCK_SIZE]
        print("perm.inv_mapping", perm.inv_mapping)
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)

        padded_ptxt = cipher.decrypt(perm.inv(ctxt))        
        ptxt = unpad(padded_ptxt, BLOCK_SIZE)

        return ptxt

    def inc_query_count(self) -> None:
        if self.query_count >= MAX_QUERIES:
            raise ValueError("too many queries")
        self.query_count += 1

    @on_command("get_token")
    def handle_get_token(self, msg):
        try:
            self.inc_query_count()

            chaff = secrets.token_bytes(MAX_BYTES - BLOCK_SIZE - TOKEN_SIZE)

            nonce, ctxt = self.encrypt(self.token + chaff)

            self.send_message({"nonce": nonce.hex(), "ctxt": ctxt.hex()})

        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("decrypt")
    def handle_decrypt(self, msg):
        try:
            self.inc_query_count()

            nonce = bytes.fromhex(msg["nonce"])
            ctxt = bytes.fromhex(msg["ctxt"])

            ptxt = self.decrypt(nonce, ctxt)
            self.send_message({"res": "Decryption succeeded."})
            del ptxt

        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        try:
            self.inc_query_count()
            print("Query count:", self.query_count)

            token = bytes.fromhex(msg["token"])
            if token == self.token:
                self.send_message({"flag": self.flag})
            else:
                self.send_message({"error": "What time is it?"})

        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    ShuffledEncryptionServer.start_server("0.0.0.0", 50402, flag=flag)


