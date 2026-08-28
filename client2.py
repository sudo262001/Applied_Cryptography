import socket
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import AES
from json import loads, dumps
from Crypto.Protocol.DH import key_agreement
from Crypto.Util.Padding import pad
from Crypto.Util import number
from Crypto.Util.Padding import unpad
from Crypto.Util import number

host = '127.0.0.1'
port = 12345

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

def ecdh_key_gen():
    client_key = ECC.generate(curve="P-256")
    client_pub = client_key.public_key().export_key(format="PEM")
    return client_key, client_pub


def kdf(x):
    return SHA256.new(x).digest()


def dcc_verify(h, signature, public_key):
    try:
        verifier = DSS.new(public_key, "fips-186-3")
        return True               
    except (ValueError, TypeError):
        return False 

def connect_to_server():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    client_key, client_pub = ecdh_key_gen()
    with client_socket:
        send_json(client_socket, {"Hashing" : "SHA256", "Key Exchange" : "ECDH",
          "Digital Signature" : "ECDHA", "Symmetric Encryption" : "AES-GCM", "client_public":client_pub})
        data = recv_json(client_socket)
        server_pub = ECC.import_key(data["server_public"]["server_public_pem"])
        signature = bytes.fromhex(data["signature"])
        session_key = key_agreement(static_priv=client_key, static_pub=server_pub, kdf=kdf)
        h = SHA256.new(client_pub.encode() + data["server_public"]["server_public_pem"].encode())
        if not dcc_verify(h, signature, server_pub):
            print("Auth Error")
            return
        print("Handshake successful. Type messages (exit to quit).")

        while True:
            msg = input("Send Message! ('esc' to exit)") 
            if(msg.lower() == 'exit'):
                print("Connection Closed")
                break
            cipher = AES.new(session_key[:16], AES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(msg.encode(), 16))
            encrypted_msg = {"Cipher Text": ciphertext}
            send_json(client_socket, encrypted_msg)
            reply = recv_json(client_socket)
            ciphertext = bytes(reply["Cipher Text"])
            cipher = AES.new(session_key[:16], AES.MODE_ECB)
            plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(plaintext, 16).decode()
            print(plaintext)
    print("Connection Terminated")

if __name__ == "__main__":
    connect_to_server()