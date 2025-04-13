import socket
import threading
import random
import math
class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.public_keys = {}

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...
        server_p, server_q = self.generate_prime(1000, 5000), self.generate_prime(1000, 5000)
        server_n = server_p * server_q
        server_phi_n = (server_p - 1) * (server_q - 1)
        server_e = random.randint(3, server_phi_n - 1)
        while math.gcd(server_e, server_phi_n) != 1:
            server_e = random.randint(3, server_phi_n - 1)
        server_public_key = f"{server_n},{server_e}"


        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            # receive client`s public key
            client_public_key = c.recv(1024).decode()
            print(f"Received client public key: {client_public_key}")
            self.public_keys[c] = client_public_key

            # print(self.clients, self.public_keys)
            # send public key to the client
            c.send(server_public_key.encode())

            # ...

            # encrypt the secret with the clients public key

            # ...

            # send the encrypted secret to a client

            # ...

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients:

            # encrypt the message

            # Отримати публічний ключ клієнта
            pub_key = self.public_keys[client]
            n, e = map(int, pub_key.split(","))

            # Зашифрувати повідомлення для цього клієнта
            encrypted_msg = [pow(ord(ch), e, n) for ch in msg]

            # Перетворити у байти і надіслати
            client.send(",".join(map(str, encrypted_msg)).encode())

    def handle_client(self, c: socket, addr):
        while True:
            msg = c.recv(1024)

            for client in self.clients:
                if client != c:
                    client.send(msg)


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



if __name__ == "__main__":
    s = Server(9001)
    s.start()
