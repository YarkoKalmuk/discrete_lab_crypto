"""module for clients"""
import socket
import threading
import random
import math
import hashlib

class Client:
    """Clients info"""
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.__p = None
        self.__q = None
        self.n = None
        self.e = None
        self.__phi_n = None
        self.__d = None
        self.server_e = None
        self.server_n = None

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs
        self.create_keys()

        # exchange public keys
        public_key = f"{self.n},{self.e}"  # Sending n and e as a public key
        self.s.send(public_key.encode())

        # receive the encrypted secret key
        server_public_key = self.s.recv(1024).decode()
        self.server_n, self.server_e = map(int, server_public_key.split(","))

        # determine encrypted block length based on server_n
        self.server_block_size = len(str(self.server_n)) - 1

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        """Reads an encrypted message"""
        while True:

            message = self.s.recv(1024).decode()
            received_hash, message, last_block_len = message.split("|")
            encrypted_blocks = [message[i:i+self.block_size+1] for i in range(0, len(message), self.block_size+1)]
            decrypted_blocks = [str(pow(int(block), self.__d, self.n)) for block in encrypted_blocks]
            decrypted_filled_blocks = [block.zfill(self.block_size) if i != len(encrypted_blocks)-1 else block.zfill(int(last_block_len))
                                for i, block in enumerate(decrypted_blocks)]
            numeric_string = "".join(decrypted_filled_blocks)

            decoded_message = "".join(chr(int(numeric_string[i:i+3])) for i in range(0, len(numeric_string), 3))

            new_hash = hashlib.sha256(decoded_message.encode()).hexdigest()
            if new_hash != received_hash:
                raise ValueError("Hashes of the same message are not the same!")

            print(decoded_message)

    def write_handler(self):
        """Writes a message and encrypts it using RSA block encoding"""
        while True:
            message = input()
            message_hash = hashlib.sha256(message.encode()).hexdigest()

            numeric_string = ''.join(f"{ord(c):03d}" for c in message)

            blocks = [numeric_string[i:i+self.server_block_size]
                      for i in range(0, len(numeric_string), self.server_block_size)]
            last_block_len = len(blocks[-1])
            encrypted_blocks = [str(pow(int(block), self.server_e, self.server_n)).zfill(self.server_block_size+1) for block in blocks]

            encrypted_message = "".join(encrypted_blocks)
            full_message = f"{message_hash}|{encrypted_message}|{last_block_len}"
            self.s.send(full_message.encode())

    @staticmethod
    def is_prime(number) -> bool:
        """Checks if a number is prime"""
        if number <2:
            return False

        for n in range(2, int(math.sqrt(number)+1)):
            if number % n == 0:
                return False
        return True

    @staticmethod
    def generate_prime(min_value, max_value) -> int:
        """Generates a random prime number in given range"""
        prime = random.randint(min_value, max_value)
        while not Client.is_prime(prime):
            prime = random.randint(min_value, max_value)
        return prime

    @staticmethod
    def mod_inverse(e, phi) -> int:
        """Finds an inversed num to e with module phi"""
        for d in range(3, phi):
            if (d*e)%phi == 1:
                return d
        raise ValueError("gcd(e, d) is not 1")

    def create_keys(self):
        """Creates public and private key for a client"""
        # private p, q
        self.__p = self.generate_prime(1000, 5000)
        self.__q = self.generate_prime(1000, 5000)
        while self.__p==self.__q:
            self.__q = self.generate_prime(1000, 5000)

        self.n = self.__p * self.__q # public key "n"
        self.__phi_n = (self.__p-1)*(self.__q-1)
        self.e =random.randint(3, self.__phi_n-1) # public key "e"
        while math.gcd(self.e, self.__phi_n) !=1 :
            self.e =random.randint(3, self.__phi_n-1)

        self.__d = self.mod_inverse(self.e, self.__phi_n) # secret key "d"
        # clients block size
        self.block_size = len(str(self.n)) - 1

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "alice")
    cl.init_connection()
