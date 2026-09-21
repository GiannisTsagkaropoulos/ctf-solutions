import secrets

from Crypto.Cipher import AES
from Crypto.Hash import Poly1305, SHA256
from Crypto.PublicKey import RSA

from boilerplate import CommandServer, on_command

RSA_KEYLEN = 2048
E = 65537
NUM_ROUNDS = 100

MOVES = ("rock", "paper", "scissors")
BEATS = {
    "rock": "paper",
    "paper": "scissors",
    "scissors": "rock",
}


class RSA_SHA256:
    @staticmethod
    def sign(key: RSA.RsaKey, message: bytes) -> bytes:
        if key.n.bit_length() != RSA_KEYLEN:
            raise ValueError("wrong RSA key length")

        m = int.from_bytes(SHA256.new(message).digest(), "big")
        return pow(m, key.d, key.n).to_bytes(RSA_KEYLEN // 8, "big")

    @staticmethod
    def verify(key: RSA.RsaKey, message: bytes, signature: bytes) -> bool:
        if key.n.bit_length() != RSA_KEYLEN:
            raise ValueError("wrong RSA key length")

        m = int.from_bytes(SHA256.new(message).digest(), "big")
        s = int.from_bytes(signature, "big")
        return pow(s, key.e, key.n) == m


class RPSServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.round = 0
        self.signature = b""
        self.tag = b""
        self.server_move: bytes | None = None

        super().__init__(*args, **kwargs)

    @on_command("get_move")
    def handle_get_move(self, msg):
        try:
            self.signature = bytes.fromhex(msg["signature"])
            self.tag = bytes.fromhex(msg["tag"])
            # My strategy is in the unique mixed Nash equilibrium and yours should too
            self.server_move = secrets.choice(MOVES)
            self.send_message({"move": self.server_move})

        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("reveal")
    def handle_reveal(self, msg):
        try:
            client_move = msg["move"]
            n = msg["n"]
            verify_key = RSA.construct((n, E))
            mac_key = bytes.fromhex(msg["mac_key"])
            nonce = self.round.to_bytes(16, "big")

            if (
                self.server_move
                or client_move not in MOVES
                or not RSA_SHA256.verify(
                    verify_key, client_move.encode(), self.signature
                )
                or Poly1305.new(
                    key=mac_key,
                    cipher=AES,
                    nonce=nonce,
                    data=client_move.encode(),
                ).digest()
                != self.tag
            ):
                self.send_message({"error": "I'll break it first, I've had enough"})
                self.close_connection()
                return

            if client_move == BEATS[self.server_move]:
                self.round += 1
                self.server_move = None
                self.signature = self.tag = b""
                self.send_message({"result": f"You won! ({self.round}/{NUM_ROUNDS})"})
            else:
                self.send_message({"result": "Tough tough luck"})
                self.close_connection()

        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("get_flag")
    def handle_get_flag(self, msg):
        if self.round >= NUM_ROUNDS:
            self.send_message({"flag": self.flag})
        else:
            self.send_message({"error": "You're falling behind"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    RPSServer.start_server("0.0.0.0", 50900, flag=flag)
