import random
from boilerplate import CommandServer, on_command
from dataclasses import dataclass
from string import ascii_letters, digits

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

BLOCK_SIZE = 16

# We take the flag and we hold the student ransom for... ONE. MILLION. POINTS.
TARGET_SCORE = 1_000_000

MAX_USERS = 20


def sample_without_special_chars(length):
    """ Sample a random byte string from secure randomness, ensuring it doesn't contain special bytes that we use as delimiters in our user record. """

    while True:
        sample = secrets.token_bytes(length)
        if b'&' not in sample and b'=' not in sample:
            return sample

@dataclass
class UserRecord:
    """ A class holding utilities for creating, encrypting, and decrypting user records. """
    username: str
    voucher: bytes
    game_random: bytes
    color: str

    @classmethod
    def create(cls, username: str, voucher: bytes):
        game_random = sample_without_special_chars(16)

        # idk i like 6-letter colors
        color = secrets.choice(["yellow", "purple", "orange", "salmon", "carrot", "maroon"])
        cls_ins = cls(username=username, voucher=voucher, game_random=game_random, color=color)
        return cls_ins

    def serialize(self) -> bytes:
        return b''.join([
            "username=".encode(),
            self.username.encode(),
            "&voucher=".encode(),
            self.voucher,
            "&color=".encode(),
            self.color.encode(),
            "&game_random=".encode(),
            self.game_random,
        ])

    def encrypt(self, master_key: bytes):
        cipher = AES.new(master_key, AES.MODE_ECB)
        return cipher.encrypt(pad(self.serialize(), BLOCK_SIZE))

    @classmethod
    def from_ciphertext(cls, ciphertext: bytes, master_key: bytes):
        """ Decrypts the user record and parses it. Raises ValueError if the record is malformed. """

        cipher = AES.new(master_key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
        print("decrypted: ", decrypted)

        try:
            parts = decrypted.split(b"&")
            data = {}
            for part in parts:
                if b"=" not in part:
                    raise ValueError(f"Invalid section in user record")

                key, value = part.split(b"=", 1)

                data[key.decode()] = value

            if "username" not in data:
                raise ValueError("Missing username in user record")
            if "voucher" not in data:
                raise ValueError("Missing voucher in user record")
            if "game_random" not in data:
                raise ValueError("Missing game_random in user record")
            if "color" not in data:
                raise ValueError("Missing color in user record")

            return cls(
                username=data["username"],
                voucher=data["voucher"],
                game_random=data["game_random"],
                color=data["color"]
            )
        except Exception as e:
            raise ValueError(f"Failed to parse user record: {e}")


class MiniServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.voucher = sample_without_special_chars(16)
        self.master_key = secrets.token_bytes(16)
        self.expired_randomness = set()
        self.score = 0
        self.num_users = 0
        print("\nInit\n, voucher:", self.voucher)
        super().__init__(*args, **kwargs)

    @on_command("create_user")
    def handle_create_user(self, msg):
        if self.num_users >= MAX_USERS:
            self.send_message({"error": "User limit reached."})
            return

        try:
            username = str(msg["username"])

            if len(username) == 0 or len(username) > 32:
                self.send_message({"error": "Username must be between 1 and 32 characters long."})
                return

            if not all(ch in ascii_letters + digits + "_" for ch in username):
                self.send_message({"error": "Username can only contain letters, digits, and underscores."})
                return

            encrypted_record = UserRecord.create(username, self.voucher).encrypt(self.master_key)
            self.num_users += 1

            self.send_message({"user_record": encrypted_record.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})
            return

    @on_command("play")
    def handle_play(self,msg):
        """ Mhh... this feels a bit unfair, doesn't it? """
        try:
            guess = int(msg["guess"])
            user_record_ctxt= bytes.fromhex(msg["user_record"])
            user_record = UserRecord.from_ciphertext(user_record_ctxt, self.master_key)
            
            # Prevent reusing the same user record to play multiple times
            if user_record.game_random in self.expired_randomness:
                self.send_message({"error": "This user record has already been used to play. Please create a new one."})
                return

            if len(user_record.game_random) > 16:
                self.send_message({"error": "Randomness in user record is too long, invalid user record."})
                return

            # Choose a random number between 0 and 2^64-1
            print("In Play")
            print("user_record.game_random: ", user_record.game_random)
            rand_bytes = random.Random(user_record.game_random).randbytes(8)
            rand_int = int.from_bytes(rand_bytes, "big")
            self.expired_randomness.add(user_record.game_random)

            if guess == rand_int:
                self.score += 1
                self.send_message({"msg": "Yay! Grooving! Smashing! Your score has been increased by 1!"})
            else:
                self.score -= 1
                self.send_message({"msg": f"Sorry, the correct number was {rand_int}. Mr. Bigglesworth got upset :("})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})
            return

    @on_command("use_voucher")
    def handle_voucher(self, msg):
        try:
            voucher = bytes.fromhex(msg["voucher"])
            print("In Play")
            print("sent voucher: ", voucher)
            print("server voucher: ", self.voucher)
            

            if len(voucher) != 16:
                self.send_message({"error": "Invalid voucher code format."})
                return

            print("self.voucher", self.voucher)
            if voucher == self.voucher:
                self.score += 10_000_000
                self.send_message({"msg": "Mhhh... My mojo!"})
            else:
                self.send_message({"msg": "Invalid voucher code."})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})
            return


    @on_command("get_flag")
    def handle_get_flag(self, msg):
        if self.score >= TARGET_SCORE:
            self.send_message({"msg": "Yeah! Yeah, baby!", "flag": self.flag})
        else:
            self.send_message({"msg": "Did you lose your mojo? You don't have enough points!"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    MiniServer.start_server("0.0.0.0", 50401, flag=flag)
