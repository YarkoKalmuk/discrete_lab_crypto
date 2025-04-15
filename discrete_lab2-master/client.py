import socket
import threading
import random
import math

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.p = None
        self.q = None
        self.n = None
        self.e = None
        self.phi_n = None
        self.d = None

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs
        self.p, self.q = self.generate_prime(1000, 5000), self.generate_prime(1000, 5000) # private p, q
        while self.p==self.q:
            self.q = self.generate_prime(1000, 5000)

        self.n = self.p * self.q # public key "n"
        self.phi_n = (self.p-1)*(self.q-1)
        self.e =random.randint(3, self.phi_n-1) # public key "e"
        while math.gcd(self.e, self.phi_n) !=1 :
            self.e =random.randint(3, self.phi_n-1)

        self.d = self.mod_inverse(self.e, self.phi_n) # secret key "d"
        # exchange public keys
        public_key = f"{self.n},{self.e}"  # Sending n and e as a public key
        self.s.send(public_key.encode())

        # receive the encrypted secret key
        self.server_public_key = self.s.recv(1024).decode()
        self.server_n, self.server_e = map(int, self.server_public_key.split(","))
        print(f"Received server public key as (n, e): ({self.server_public_key})")

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        """Reads encryptde message"""
        while True:
            message = self.s.recv(1024).decode()

            # decrypt message with the secrete key

            encrypted_numbers = list(map(int, message.split(",")))
            message_encoded = [pow(ch, self.d, self.n) for ch in encrypted_numbers]
            for ch in encrypted_numbers:
                print(f'ch: {ch}')
                print(f'd: {self.d}')
                print(f'n: {self.n}')
                print(f'pow: {pow(ch, self.d, self.n)}')
            message = "".join(chr(ch) for ch in message_encoded)

            print(message)

    def write_handler(self):
        """Writes a message and encrypts it"""
        while True:
            message = input()

            # encrypt message with the secrete key
            message_encoded = [ord(ch) for ch in message]

            # (m^e)modn = c
            ciphered_text = [pow(ch, self.server_e, self.server_n) for ch in message_encoded]
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
        print(f'e: {e}')
        for d in range(3, phi):
            if (d*e)%phi == 1:
                return d
        raise ValueError("gcd(e, d) is not 1")

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "gay")
    cl.init_connection()
