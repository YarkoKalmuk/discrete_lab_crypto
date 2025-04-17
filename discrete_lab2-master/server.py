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

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()


    def decode_message(self, encrypted_part, last_block_len):
        """Decodes a message using block rsa"""
        encrypted_blocks = [encrypted_part[i:i+self.block_size+1] for i in range(0, len(encrypted_part), self.block_size+1)]
        decrypted_blocks = [str(pow(int(block), self.__d, self.n)) for block in encrypted_blocks]
        decrypted_filled_blocks = [block.zfill(self.block_size) if i != len(encrypted_blocks)-1 else block.zfill(int(last_block_len))
                            for i, block in enumerate(decrypted_blocks)]
        numeric_string = "".join(decrypted_filled_blocks)
        decoded_message = "".join(chr(int(numeric_string[i:i+3])) for i in range(0, len(numeric_string), 3))
        return decoded_message

    def encode_message(self, message, client_n, client_e):
        """Encodes a message using block rsa"""
        client_block_size = len(str(client_n))-1
        numeric_string = ''.join(f"{ord(c):03d}" for c in message)

        blocks = [numeric_string[i:i+client_block_size] for i in range(0, len(numeric_string), client_block_size)]
        last_block_size = len(blocks[-1])
        encrypted_blocks = [str(pow(int(block), client_e, client_n)).zfill(client_block_size+1) for block in blocks]

        encrypted_message = "".join(encrypted_blocks)
        full_message = f"{encrypted_message}|{last_block_size}"
        return full_message


    def broadcast(self, msg: str):
        """Sends a message to all clients"""
        for client in self.clients:

            # encrypt the message

            pub_key = self.public_keys[client]
            client_n, client_e = map(int, pub_key.split(","))
            encoded_message = self.encode_message(msg, client_n, client_e)

            msg_hash = hashlib.sha256(msg.encode()).hexdigest()
            full_message = f"{msg_hash}|{encoded_message}"
            client.send(full_message.encode())

    def handle_client(self, c: socket, addr):
        """Handles a wanted client"""
        while True:
            sender_name = self.username_lookup[c]
            user_getter = None
            msg = c.recv(1024).decode()

            # check if there is a hash in a message
            try:
                received_hash, encrypted_part, last_block_len = msg.split("|")
            except ValueError:
                print("Please, calculate the hash of a message and send it as "\
                      "'hash|encrypted_message'")
                continue

            decoded_message = self.decode_message(encrypted_part, last_block_len)

            # check if hashes are the same
            new_hash = hashlib.sha256(decoded_message.encode()).hexdigest()
            if new_hash != received_hash:
                raise ValueError("Hashes of the same message are not the same!")

            # look to whom is this message for
            match = re.search(r'@\w+:', decoded_message)
            if match:
                user_getter = match.group(0)[:-1]
                message_to_send = decoded_message[match.end():].lstrip()
                message_to_send = f"From @{sender_name}: "+message_to_send
            else:
                raise ValueError("Please, correctly type the name of \
the person you want to send a message to")

            for client in self.clients:
                if self.username_lookup[client] == user_getter[1:]:
                    # get the wanted client`s keys
                    pub_key = self.public_keys[client]
                    client_n, client_e = map(int, pub_key.split(","))
                    encoded_message = self.encode_message(message_to_send, client_n, client_e)

                    msg_hash = hashlib.sha256(message_to_send.encode()).hexdigest()
                    full_message = f"{msg_hash}|{encoded_message}"
                    client.send(full_message.encode())


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
        # block size
        self.block_size = len(str(self.n)) - 1

if __name__ == "__main__":
    s = Server(9001)
    s.start()
