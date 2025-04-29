import socket
import json
import time
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets
import base64
SERVER_addr="192.168.43.137"
PORT=8000
clients = {}
groups= {}
def generate_aes_key():
    password = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)
def encrypt_message(aes_key, plaintext):
    nonce = secrets.token_bytes(12)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext
def decrypt_message(aes_key, encrypted_message):
    nonce = encrypted_message[:12]
    tag = encrypted_message[12:28]
    ciphertext = encrypted_message[28:]
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
def encrypt_public_key(public_key, data):
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
def send_message_user(receiver,sender, message,digsign):
        msg = {
            "type": "UserMessage",
            "user": sender,
            "message": message,
            "digsign": digsign
        }
        clients[receiver]["client"].send(encrypt_message(clients[receiver]["aes_key"],json.dumps(msg).encode('utf-8')))
def send_message_group(receiver,sender,group, message,digsign):
        msg = {
            "type": "GroupMessage",
            "user": sender,
            "group":group,
            "message": message,
            "digsign": digsign
        }
        clients[receiver]["client"].send(encrypt_message(clients[receiver]["aes_key"],json.dumps(msg).encode('utf-8')))
def handle_client(client_socket):
    try:
        public_key_pem=client_socket.recv(4096)
        public_key=serialization.load_pem_public_key(public_key_pem)
        aes_key = generate_aes_key()
        client_socket.send(encrypt_public_key(public_key,aes_key))
        username=decrypt_message(aes_key,client_socket.recv(1024)).decode('utf-8')
        clients[username]={
            "client":client_socket,
            "aes_key":aes_key,
            "public_key":public_key_pem,
        }
        while True:
            packet=json.loads(decrypt_message(aes_key,client_socket.recv(4096)).decode('utf-8'))
            if packet["type"]=="GetUsersList":
                data={
                    "type":"UsersList",
                    "data":[x for x in list(clients.keys()) if x != username]
                }
                client_socket.send(encrypt_message(aes_key,json.dumps(data).encode('utf-8')))
            if packet["type"]=="GetGroupsList":
                data={
                    "type":"GroupsList",
                    "data":[x for x in list(groups.keys()) if username in groups[x]]
                }
                client_socket.send(encrypt_message(aes_key,json.dumps(data).encode('utf-8')))
            elif packet["type"]=="UserMessage":
                send_message_user(packet["user"],username,packet["message"],packet["digsign"])
            elif packet["type"]=="GroupMessage":
                for _ in [x for x in groups[packet["group"]] if x != username and x in list(clients.keys())]:
                    send_message_group(_,username,packet["group"],packet["message"],packet["digsign"])
            elif packet["type"]=="AddGroup":
                groups[packet["group"]]=packet["list"]+[username]
            elif packet["type"]=="UserFile":
                receiver=packet["user"]
                packet["user"]=username
                clients[receiver]["client"].send(encrypt_message(clients[receiver]["aes_key"],json.dumps(packet).encode('utf-8')))
                time.sleep(0.1)
                bytes_received = 0
                while bytes_received < packet["filesize"]:
                    data = decrypt_message(aes_key,client_socket.recv(1024))
                    bytes_received += len(data)
                    clients[receiver]["client"].send(encrypt_message(clients[receiver]["aes_key"],data))
            elif packet["type"]=="GroupFile":
                packet["user"]=username
                for _ in [x for x in groups[packet["group"]] if x != username and x in list(clients.keys())]:
                    clients[_]["client"].send(encrypt_message(clients[_]["aes_key"],json.dumps(packet).encode('utf-8')))
                time.sleep(0.1)
                bytes_received = 0
                while bytes_received < packet["filesize"]:
                    data = decrypt_message(aes_key,client_socket.recv(1024))
                    bytes_received += len(data)
                    for _ in [x for x in groups[packet["group"]] if x != username and x in list(clients.keys())]:
                        clients[_]["client"].send(encrypt_message(clients[_]["aes_key"],data))
            elif packet["type"]=="GetPublicKey":
                pk={}
                if "user" in list(packet.keys()):
                    pk={
                        "type":"UserPublicKey",
                        "user":packet["user"],
                        "publickey":base64.b64encode(clients[packet["user"]]["public_key"]).decode('utf-8')
                    }
                elif "group" in list(packet.keys()):
                    pk={
                        "type":"GroupPublicKeys",
                        "group":packet["group"],
                        "publickeys":{}
                    }
                    for _ in [x for x in groups[packet["group"]] if  x!=username and x in list(clients.keys())]:
                        pk["publickeys"][_]=base64.b64encode(clients[_]["public_key"]).decode('utf-8')
                client_socket.send(encrypt_message(aes_key,json.dumps(pk).encode('utf-8')))

            elif packet["type"]=="SessionKeyExchange":
                receiver=packet["user"]
                packet["user"]=username
                clients[receiver]["client"].send(encrypt_message(clients[receiver]["aes_key"],json.dumps(packet).encode('utf-8')))
            elif packet["type"]=="GroupSessionKeyExchange":
                clients[packet["user"]]["client"].send(encrypt_message(clients[packet["user"]]["aes_key"],json.dumps(packet).encode('utf-8')))
    except:
        pass
    finally:
        print(f"[Serwer] {username} opuścił czat.")
        del clients[username]
        client_socket.close()
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_addr, PORT))
    server.listen(5)
    print("[Serwer] Oczekiwanie na połączenia...")

    while True:
        client_socket, addr = server.accept()
        print(f"[Serwer] Połączono z {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
