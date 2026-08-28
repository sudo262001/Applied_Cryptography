import socket
import threading
from json import loads, dumps
from random import randrange
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from crypto import xgcd, InverseMod,RandomPrime
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA512
from Crypto.Signature import DSS

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

class Party:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.a = randrange(2, p - 1)
        self.A = pow(g, self.a, p)
        self.s = None

    def compute_shared(self, B):
        self.s = pow(B, self.a, self.p)

host = '127.0.0.1'
port = 12345

def kdf(x):
    return SHA512.new(x).digest()

def diffie_hellman_key_exchange(A, p, g):
    server = Party(p, g)
    server.compute_shared(A)
    return server

def elliptical_curve_diffie_hellman_key_exchange(client_pub_pem):
    client_pub = ECC.import_key(client_pub_pem)
    server_key = ECC.generate(curve="P-256")
    server_pub_pem = server_key.public_key().export_key(format="PEM")
    ecdh_shared_key = key_agreement(static_priv=server_key, static_pub=client_pub,kdf=kdf)
    return server_pub_pem, ecdh_shared_key, server_key


def dcc_sign(data, private_key):
    h = SHA512.new(data)
    signer = DSS.new(private_key, "fips-186-3")
    signature = signer.sign(h)
    return signature.hex()

def rsa_sign(data, private_key):

    N, d = private_key
    h = int.from_bytes(SHA512.new(data).digest()) % N
    return pow(h, d, N)

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

def generate_rsa_keys():
    p = 604277
    q = 900577
    N = p * q
    phi = (p-1) * (q-1)
    while True:
        e = randrange(2, phi -1)
        g,_,_ = xgcd(e, phi)
        if g == 1:
            break
    d = InverseMod(e, phi)
    return (N, e), (N, d)

def handle_suits(data):
    suite = data
    if(suite["Key Exchange"] == "Diffie-Hellman"):
        A = suite["A"]
        p = suite["p"]
        g = suite["g"]
        server = diffie_hellman_key_exchange(A, p, g)
        rsa_public, rsa_private = generate_rsa_keys()
        data_to_sign = (str(A)+str(server.A)+str(p) + str(g)).encode()
        signature = rsa_sign(data_to_sign, rsa_private)
        server_public = {"B": server.A, "N": rsa_public[0], "e": rsa_public[1]}
        shared_key = server.s
        return signature, shared_key, server_public
    if(suite["Key Exchange"] == "ECDH"):
        client_pub_pem = data["client_public"]
        server_pub_pem, shared_key, server_key = elliptical_curve_diffie_hellman_key_exchange(client_pub_pem)
        data_to_sign = client_pub_pem.encode() + server_pub_pem.encode()
        signature = dcc_sign(data_to_sign, server_key)
        server_public = {"server_public_pem": server_pub_pem}
        return signature, shared_key, server_public

def handle_clients(connection, address):
    print(f"Connection established with {address}")
    try:
        # Handshake
        data = recv_json(connection)
        if not data:
            connection.close()
            return
        signature, shared_key, server_public = handle_suits(data)
        handshake = {"signature": signature, "server_public": server_public}
        send_json(connection, handshake)
        print(f"Handshake complete with {address}")
    except Exception as e:
        print(f"Handshake failed with {address}: {e}")
        connection.close()
        return

    try:
        while True:
            client_msg = recv_json(connection)
            if client_msg is None:
                break

            if isinstance(shared_key, bytes):
                # ECDH (client2) – shared_key is already bytes
                aes_key = shared_key[:16] if len(shared_key) >= 16 else shared_key.ljust(16, b'\x00')
            else:
                # DH (client1) – shared_key is integer
                shared_bytes = str(shared_key).encode()
                aes_key = SHA512.new(shared_bytes).digest()[:16]

            if "Iv" in client_msg:          # Suite1 (AES‑CBC)
                cipher_text = bytes.fromhex(client_msg["Cipher Text"])
                iv = bytes.fromhex(client_msg["Iv"])
                plain_text = aes_decrypt(aes_key, iv, cipher_text).decode()
                mode = "CBC"
            else:                           # Suite2 (AES‑ECB)
                cipher_text = bytes.fromhex(client_msg["Cipher Text"])
                cipher = AES.new(aes_key, AES.MODE_ECB)
                plain_text = cipher.decrypt(cipher_text).decode()
                plain_text = unpad(plain_text)
                mode = "ECB"

            # Show the decrypted message to the server operator
            print(f"\n[Client {address}]: {plain_text}")

            # Ask for the server's reply
            reply = input("Server reply: ")
            if reply.lower() == "exit":
                break

            # Encrypt the reply using the same mode
            if mode == "CBC":
                iv2, cipher_text2 = aes_encrypt(aes_key, reply.encode())
                encrypted_reply = {"Iv": iv2.hex(), "Cipher Text": cipher_text2.hex()}
            else:  # ECB
                cipher2 = AES.new(aes_key, AES.MODE_ECB)
                ciphertext2 = cipher2.encrypt(reply.encode(), 16)
                encrypted_reply = {
                    "Cipher Text": ciphertext2.hex()
                }

            send_json(connection, encrypted_reply)

    except (ConnectionError, EOFError) as e:
        print(f"Connection lost with {address}: {e}")
    finally:
        connection.close()
        print(f"Connection closed for {address}")
            
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print("Server Listening on port {port}")
    while True:
        connection, address = server.accept()
        thread = threading.Thread(target=handle_clients, args=(connection, address))
        thread.start()
        print(f"Active Connections: {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()