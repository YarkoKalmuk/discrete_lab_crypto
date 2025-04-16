"""module for a server"""
import socket
import threading
import random
import math
import re
import hashlib
class Server:
    """Server"""

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.public_keys = {}
        self.server_private_key = None
        self.__p = None
        self.__q = None
        self.__phi_n = None
        self.n = None
        self.e = None
        self.__d = None

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...
        self.create_keys()


        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            # receive client`s public key
            client_public_key = c.recv(1024).decode()
            self.public_keys[c] = client_public_key

            # send public key to the client
            server_public_key = f"{self.n},{self.e}"
            c.send(server_public_key.encode())


            print(f"{username} has succesfully connected")
            # ...

            # encrypt the secret with the clients public key

            # ...

            # send the encrypted secret to a client

            # ...

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        """Sends a message to all clients"""
        for client in self.clients:

            # encrypt the message

            # Get the client`s public key
            pub_key = self.public_keys[client]
            client_n, client_e = map(int, pub_key.split(","))

            # Encrypt the message for the client
            encrypted_msg = [pow(ord(ch), client_e, client_n) for ch in msg]

            # Перетворити у байти і надіслати
            client.send(",".join(map(str, encrypted_msg)).encode())

    def handle_client(self, c: socket, addr):
        """Handles a wanted client"""
        while True:
            sender_name = self.username_lookup[c]

            user_getter = None
            msg = c.recv(1024)
            new_msg = msg.decode()

            # check if there is a hash in a message
            try:
                received_hash, encrypted_part = new_msg.split("|", 1)
            except ValueError:
                print("Please, calculate the hash of a message and send it as "\
                      "'hash|encrypted_message'")
                continue

            # decrypt the message with the server`s keys
            encrypted_numbers = list(map(int, encrypted_part.split(",")))
            message_encoded = [pow(n, self.__d, self.n) for n in encrypted_numbers]
            message = "".join(chr(ch) for ch in message_encoded)

            # check if hash is the same
            new_hash = hashlib.sha256(message.encode()).hexdigest()
            if new_hash != received_hash:
                raise ValueError("Hashes of the same message are not the same!")

            # look to whom is this message for
            match = re.search(r'@\w+:', message)
            if match:
                user_getter = match.group(0)[:-1]
                message_to_send = message[match.end():].lstrip()
                message_to_send = f"From @{sender_name}: "+message_to_send

            else:
                raise ValueError("Please, correctly type the name of \
the person you want to send a message to")

            for client in self.clients:
                if self.username_lookup[client] == user_getter[1:]:
                    # get the wanted client`s keys
                    pub_key = self.public_keys[client]
                    client_n, client_e = map(int, pub_key.split(","))

                    msg_for_user_nums = [ord(ch) for ch in message_to_send]
                    user_msg_encoded = [pow(n, client_e, client_n) for n in msg_for_user_nums]
                    full_user_encoded_msg = ",".join(map(str, user_msg_encoded))
                    client.send(full_user_encoded_msg.encode())


    @staticmethod
    def generate_prime(min_value, max_value) -> int:
        """Generates a random prime number in given range"""
        prime = random.randint(min_value, max_value)
        while not Server.is_prime(prime):
            prime = random.randint(min_value, max_value)
        return prime


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
    def mod_inverse(e, phi) -> int:
        """Finds an inversed num to e with module phi"""
        for d in range(3, phi):
            if (d*e)%phi == 1:
                return d
        raise ValueError("gcd(e, d) is not 1")

    def create_keys(self):
        """Creates public and private key for a server"""
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
    s = Server(9001)
    s.start()
