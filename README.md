# cli-chat

## What is that?

cli-chat is a simple tool cli for secure chatting written in python.

## Installation

Just clone repository and run [chat.py](https://github.com/Akamiblade1297/cli-chat/blob/master/chat.py) file with python compiler. It should be cross-platform.  
You would also want to install python-pycryptodome and python-cryptography libraries.  

```
pip install pycryptodome
pip install cryptography
```

## Usage
```
python chat.py <Mode> <IP_Adress> <Port> <Username> <Password>
```
*Note: on UNIX systems you may just run ./chat*  

**Mode** specifies in which mode you run: Server(serv) or Client(clnt). Server listens on its own adress and Client connects to it, so Server should run first.  

**IP_Adress** specifies the IP adress of server to connect, or to listen if you are the server.  
  
**Port** specifies the Port of server to connect, or to listen if you're the server.  
  
**Username** specifies your Username. It doesn't affect anything, but your appearence in chat.  
*Note: Username shouldn't be larger then 30 bytes. 1 Byte is 1 Symbol in ASCII, but in UTF symbols might be larger*  
  
**Password** password is used to generate MACs for public keys to protect connection from MITM Attack, it's still not necessary tho.  

You also should set up a Virtual Network to be able to connect to each other. (Radmin VPN or Hamachi will do it)

### Example

```
$ ./chat.py serv 127.0.0.1 3000 A97
WARNGING: connection without a password is vulnerable to MITM Attack.

Waiting for client to connect..
Connection received from client on 127.0.0.1:58610. Exchanging session key.
Session key exchanged. Connection is secure.

The begining of chat with Somebody
Somebody: Hello, A97!
> Hello, Somebody!
Catched an unexpected error: Nonce cannot be empty

Connection was closed.
```
```
$ ./chat.py 127.0.0.1 3000 Somebody clnt
WARNGING: connection without a password is vulnerable to MITM Attack.

Connecting to server..
Connected to server on 127.0.0.1:3000. Exchanging session key.
Session key exchanged. Connection is secure.

The begining of chat with A97
> Hello, A97!
A97: Hello, Somebody!
> ^C
Connection was closed.
```

## Is that really secure?

Yes. It's using ECDHE Algorithm for exchanging Session Key, HKDF-SHA256 diveration and AES-256 for encrypting all messages.  
It is commonly used in websites.  

Since I can't obtain a trusted CA signature, I use Password to generate a key using PBKDF2, that is used generate MACs for public keys.  
That way, if MITM Attack happens, they wouldn't be able to generate new MAC without having a key.

---

P.S. I made this project just for fun and education.
