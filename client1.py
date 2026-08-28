import socket
from json import loads, dumps
from Crypto.Cipher import AES
from random import randrange
from Crypto.Hash import SHA512
from crypto import GeneratePrimeGeneratorPair, xgcd, InverseMod

def send_json(sock, obj):
    data = dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4, "big"))
    sock.sendall(data)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Connection closed")
        data += packet
    return data


def recv_json(sock):
    length = int.from_bytes(recv_exact(sock, 4), "big")
    data = recv_exact(sock, length)
    return loads(data.decode())

suite = {"Hashing" : "SHA512", "Key Exchange" : "Diffie-Hellman",
          "Digital Signature" : "RSA", "Symmetric Encryption" : "AES-CBC"}

class Party:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.a = randrange(2, p - 1)
        self.A = pow(g, self.a, p)
        self.s = None

    def compute_shared(self, B):
        self.s = pow(B, self.a, self.p)

p = randrange(1000,100000,1)
g = randrange(1000, 100000, 1)
client = Party(p, g)

def dh_shared_key(data):
    client.compute_shared(data["server_public"]["B"])
    return client.s

def rsa_verify(data, signature, public_key):
    N, e = public_key
    h = int.from_bytes(SHA512.new(data).digest()) % N
    return pow(signature, e, N) == h

def verify_server(data):
    server_public = data["server_public"]["N"], data["server_public"]["e"]
    data_signed = (str(client.A) + str(data["server_public"]["B"]) + str(p) + str(g)).encode()
    signature = data["signature"]
    return rsa_verify(data_signed, signature, server_public)

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    return data[:-data[-1]]

def aes_encrypt(key, plaintext):
    iv = randrange(1 << 128).to_bytes(16, "big")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(plaintext))

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext))

def connect_to_server():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with client_socket:
        client_socket.connect(('127.0.0.1', 12345))
        send_json(client_socket, {"ClientName" : "Client1", "Hashing" : "SHA512", "Key Exchange" : "Diffie-Hellman",
          "Digital Signature" : "RSA", "Symmetric Encryption" : "AES-CBC", "p" : p, "g" : g, "A": client.A})
        data = recv_json(client_socket)
        if not verify_server(data):
            print("Auth Error")
            client_socket.close()
            return
        shared_key = dh_shared_key(data)
        while True:
            msg = input("Send Message! ('exit' to quit)")
            if(msg.lower() == 'exit'):
                print("Connection Closed")
                break
            shared_bytes = str(shared_key).encode()
            aes_key = SHA512.new(shared_bytes).digest()[:16]
            iv, ciphertext = aes_encrypt(aes_key, msg.encode())
            msg_encrypted = {"Cipher Text": ciphertext.hex(), "Iv": iv.hex()}
            send_json(client_socket, msg_encrypted)
            data = recv_json(client_socket)
            plain_text = aes_decrypt(aes_key, bytes.fromhex(data["Iv"]), bytes.fromhex(data["Cipher Text"])).decode()
            print(f"Server Reply {plain_text}")
    print("Connection Terminated")

if __name__ == "__main__":
    connect_to_server()