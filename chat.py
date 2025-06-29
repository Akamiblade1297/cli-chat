#!/bin/python
import socket
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from typing import Callable

def Exchange_Key_Server(conn: socket.socket) -> bytes:
    private_key = x25519.X25519PrivateKey.generate()
    public_key  = private_key.public_key()
    
    public_key_clnt = x25519.X25519PublicKey.from_public_bytes(conn.recv(32))
    conn.send(public_key.public_bytes_raw())

    shared_key = private_key.exchange(public_key_clnt)
    return shared_key

def Exchange_Key_Client(conn: socket.socket) -> bytes:
    private_key = x25519.X25519PrivateKey.generate()
    public_key  = private_key.public_key()
    
    conn.send(public_key.public_bytes_raw())
    public_key_serv = x25519.X25519PublicKey.from_public_bytes(conn.recv(32))

    shared_key = private_key.exchange(public_key_serv)
    return shared_key

def Derive_Session_Key(key: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'Session Key.',
        backend=default_backend()
    ).derive(key)

def Encrypt_Data(data: bytes, key: bytes) -> bytes:
    nonce = get_random_bytes(12)
    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    enc, mac = aes.encrypt_and_digest(data)
    return mac+nonce+enc

def Decrypt_Data(data: bytes, key: bytes) -> bytes:
    mac   = data[:16]
    nonce = data[16:28]
    enc   = data[28:]
    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return aes.decrypt_and_verify(enc, mac)

def Handle_Server(conn: socket.socket, name: str, key: bytes):
    msg = Decrypt_Data(conn.recv(1024), key)
    print(f"{name}: {msg.decode()}")
    ans = input('> ')
    conn.send(Encrypt_Data(ans.encode(),key))

def Handle_Client(conn: socket.socket, name: str, key: bytes):
    msg = input('> ')
    conn.send(Encrypt_Data(msg.encode(),key))
    ans = Decrypt_Data(conn.recv(1024),key)
    print(f"{name}: {ans.decode()}")

def Handle_Connection(func: Callable, conn: socket.socket, name: str, key: bytes):
    print(f"\nThe begining of chat with {name}")
    try:
        while True:
            func(conn, name, key)
    except EOFError: ''
    except KeyboardInterrupt: ''
    except BrokenPipeError: ''
    except Exception as e:
        print(f"Catched an unexpected error: {e}")
    finally:
        print("\nConnection was closed.")


HOST      = sys.argv[1]
PORT      = int(sys.argv[2])
HOST_NAME = sys.argv[3]
MODE      = sys.argv[4]

host = socket.socket()
if MODE == "serv":
    host.bind(( HOST, PORT ))
    host.listen(1)
    print('Waiting for client to connect..')
    conn, addr = host.accept()
    print(f'Connection received from client on {addr[0]}:{addr[1]}. Exchanging session key.')
    shared_key = Exchange_Key_Server(conn)
    key = Derive_Session_Key(shared_key)
    print("Session key exchanged. Connection is secure.")

    CLNT_NAME = Decrypt_Data(conn.recv(64), key).decode()
    conn.send(Encrypt_Data(HOST_NAME.encode(), key))
    
    Handle_Connection(Handle_Server, conn, CLNT_NAME, key)

elif MODE == "clnt":
    print("Connecting to server..")
    host.connect((HOST, PORT))
    conn = host

    print(f'Connected to server on {HOST}:{PORT}. Exchanging session key.')
    shared_key = Exchange_Key_Client(conn)
    key = Derive_Session_Key(shared_key)
    print("Session key exchanged. Connection is secure.")

    conn.send(Encrypt_Data(HOST_NAME.encode(), key))
    SERV_NAME = Decrypt_Data(conn.recv(64), key).decode()

    Handle_Connection(Handle_Client, host, SERV_NAME, key)
else:
    raise KeyError("Invalid Mode, it must be 'serv' or 'clnt', but not", MODE)
