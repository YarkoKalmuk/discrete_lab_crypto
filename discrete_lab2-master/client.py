"""module for clients"""
import socket
import threading
import random
import math

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

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        """Reads an encrypted message"""
        while True:
            message = self.s.recv(1024).decode()

            # decrypt the message with the secrete key

            encrypted_numbers = list(map(int, message.split(",")))
            decoded_nums = [pow(n, self.__d, self.n) for n in encrypted_numbers]
            decoded_message = "".join(chr(ch) for ch in decoded_nums)

            print(decoded_message)

    def write_handler(self):
        """Writes a message and encrypts it"""
        while True:
            message = input()

            # encrypt message with the server secrete key
            message_encoded = [ord(ch) for ch in message]

            # (m^e)modn = c
            ciphered_text = [pow(n, self.server_e, self.server_n) for n in message_encoded]
            encrypted_message = ",".join(map(str, ciphered_text))

            self.s.send(encrypted_message.encode())

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


if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "ustym_2")
    cl.init_connection()
