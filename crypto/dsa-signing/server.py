import secrets

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Util.number import getPrime, isPrime

from boilerplate import CommandServer, on_command


class DSSSigner(DSS.DssSigScheme):
    """A custom signature scheme that implements DSA signing and verification

    The important changes are that:
        - Any hash is valid (so we can use CMAC output as a hash)
        - It allows for |q|=128, which is smaller than the minimum allowed by PyCryptodome's implementation,
          so that the 16-byte output of CMAC fits exactly into q.
    """

    def __init__(self, key, q: int):
        self._q = q
        super().__init__(key, "binary", order=Integer(q))

    def _valid_hash(self, _):
        # Allow any hash algorithm to be used
        return True

    def _compute_nonce(self, _):
        return secrets.randbelow(self._q - 1) + 1


def _generate_dsa_domain(p_bits=1024, q_bits=128):
    # Generate a q_bits-bit prime q, then find a p_bits-bit safe prime p = k*q + 1
    while True:
        q = getPrime(q_bits)
        for _ in range(20000):
            k = secrets.randbits(p_bits - q_bits) & ~1  # even, so p = k*q+1 is odd
            p = k * q + 1
            if p.bit_length() == p_bits and isPrime(p):
                break
        else:
            continue
        # Find a generator of the subgroup of order q
        for h in range(2, 1000):
            g = pow(h, (p - 1) // q, p)
            if g != 1:
                return p, q, g


class SigningServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        # 1024-bit p, 128-bit q: intentionally set so that CMAC (16-byte output) fits q exactly
        self.p, self.q, self.g = _generate_dsa_domain()
        x = secrets.randbelow(self.q - 1) + 1
        y = pow(self.g, x, self.p)
        self.sign_key = DSA.construct((y, self.g, self.p, self.q, x))
        self.pub_key = self.sign_key.public_key()
        super().__init__(*args, **kwargs)

    @on_command("sign")
    def handle_sign(self, msg):
        # TODO: verify that this implementation actually works before deploying
        # for now, just return an error message since we haven't implemented signing yet
        hasher = CMAC.new(bytes(16), ciphermod=AES)
        m = msg["message"]
        hasher.update(m.encode())
        signer = DSSSigner(self.sign_key, self.q)
        signature = signer.sign(hasher)
        print(signature)
        self.send_message({"signature": signature.hex()})
        self.send_message(
            {
                "error": "Don't you know I still believe that you will be here and give me a sign?"
            }
        )

    @on_command("public_key")
    def handle_public_key(self, _):
        self.send_message({"public_key": self.pub_key.export_key(format="DER").hex()})

    @on_command("verify")
    def handle_verify(self, msg):
        try:
            hasher = CMAC.new(bytes(16), ciphermod=AES)
            m = bytes.fromhex(msg["message"])
            hasher.update(m)

            if int.from_bytes(hasher.digest(), "big") % self.q == 0:
                self.send_message({"error": "Hash computation failed"})

            verifier = DSSSigner(self.pub_key, self.q)

            try:
                # This will raise a ValueError if the signature is invalid
                verifier.verify(hasher, bytes.fromhex(msg["signature"]))
            except ValueError:
                self.send_message({"error": "Something wasn't right here."})
                return

            # Are you an admin?

            key, val = m.split(b"&", 1)[0].split(b"=", 1)
            if key != b"who_is_it" or val != b"its_britney":
                self.send_message({"error": "Boy, you got me blinded."})
                return
            else:
                self.send_message({"flag": self.flag})

        except Exception as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})
            return


if __name__ == "__main__":
    flag = "flag{test_flag}"
    SigningServer.start_server("0.0.0.0", 50901, flag=flag)
