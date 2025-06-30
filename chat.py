#!/bin/python
import socket
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Callable

def HMAC_Update(key: bytes, data: bytes) -> object:
    hmac_obj = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac_obj.update(data)
    return hmac_obj

def Derive_Session_Key(key: bytes) -> bytes:
    return HKDF (
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'Session Key',
        backend=default_backend()
    ).derive(key)

def Get_PassKey(salt: bytes) -> bytes:
    if not PASSWORD:
        raise TypeError("No password, can't generate pass key.")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000,
        backend=default_backend()
    ).derive(PASSWORD)

def Exchange_Key_Server(conn: socket.socket) -> bytes:
    private_key = x25519.X25519PrivateKey.generate()
    public_key  = private_key.public_key()

    if PASSWORD:
        data        = conn.recv(96)
        salt        = data[  :16]
        nonce       = data[16:32]
        mac         = data[32:64]
        pbkey_bytes = data[64:  ]

        PASS_KEY = Get_PassKey(salt)
        hmac_obj = HMAC_Update(PASS_KEY, pbkey_bytes + nonce)
        hmac_obj.verify(mac)

        public_key_clnt = x25519.X25519PublicKey.from_public_bytes(pbkey_bytes)

        nonce       = get_random_bytes(16)
        pbkey_bytes = public_key.public_bytes_raw()
        mac = hmac_obj = HMAC_Update(PASS_KEY, pbkey_bytes + nonce).finalize()

        conn.send( nonce + mac + pbkey_bytes ) # 16 + 32 + 32 = 80
    else:
        public_key_clnt = x25519.X25519PublicKey.from_public_bytes(conn.recv(32))
        conn.send(public_key.public_bytes_raw())

    shared_key = private_key.exchange(public_key_clnt)
    return shared_key

def Exchange_Key_Client(conn: socket.socket) -> bytes:
    private_key = x25519.X25519PrivateKey.generate()
    public_key  = private_key.public_key()

    if PASSWORD:
        salt        = get_random_bytes(16)
        nonce       = get_random_bytes(16)
        pbkey_bytes = public_key.public_bytes_raw()

        PASS_KEY = Get_PassKey(salt)     
        mac = hmac_obj = HMAC_Update(PASS_KEY, pbkey_bytes + nonce).finalize()

        conn.send( salt + nonce + mac + pbkey_bytes ) # 16 + 16 + 32 + 32 = 96 bytes

        data        = conn.recv(80)
        nonce       = data[  :16]
        mac         = data[16:48]
        pbkey_bytes = data[48:  ]

        hmac_obj = HMAC_Update(PASS_KEY, pbkey_bytes + nonce)
        hmac_obj.verify(mac)

        public_key_serv = x25519.X25519PublicKey.from_public_bytes(pbkey_bytes)
    else: 
        conn.send(public_key.public_bytes_raw())
        public_key_serv = x25519.X25519PublicKey.from_public_bytes(conn.recv(32))

    shared_key = private_key.exchange(public_key_serv)
    return shared_key

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
        print(f"\033[31mCatched an unexpected error: {e}\033[0m")
    finally:
        print("\n\033[31mConnection was closed.\033[0m")


MODE      = sys.argv[1]
HOST      = sys.argv[2]
PORT      = int(sys.argv[3])
HOST_NAME = sys.argv[4]
try:
    PASSWORD = sys.argv[5].encode()
except:
    print("\033[33mWARNGING: connection without a password is vulnerable to MITM Attack.\n\033[0m")
    PASSWORD = False

host = socket.socket()
if MODE == "serv":
    host.bind(( HOST, PORT ))
    host.listen(1)
    print('\033[32mWaiting for client to connect..\033[0m')
    conn, addr = host.accept()
    print(f'\033[32mConnection received from client on {addr[0]}:{addr[1]}. Exchanging session key.\033[0m')
    shared_key = Exchange_Key_Server(conn)
    key = Derive_Session_Key(shared_key)
    print("\033[32mSession key exchanged. Connection is secure.\033[0m")

    CLNT_NAME = Decrypt_Data(conn.recv(64), key).decode()
    conn.send(Encrypt_Data(HOST_NAME.encode(), key))
    
    Handle_Connection(Handle_Server, conn, CLNT_NAME, key)

elif MODE == "clnt":
    print("\033[32mConnecting to server..\033[0m")
    host.connect((HOST, PORT))
    conn = host

    print(f'\033[32mConnected to server on {HOST}:{PORT}. Exchanging session key.\033[0m')
    shared_key = Exchange_Key_Client(conn)
    key = Derive_Session_Key(shared_key)
    print("\033[32mSession key exchanged. Connection is secure.\033[0m")

    conn.send(Encrypt_Data(HOST_NAME.encode(), key))
    SERV_NAME = Decrypt_Data(conn.recv(64), key).decode()

    Handle_Connection(Handle_Client, host, SERV_NAME, key)
else:
    raise KeyError("Invalid Mode, it must be 'serv' or 'clnt', but not", MODE)
