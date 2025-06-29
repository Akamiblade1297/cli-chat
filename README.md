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

`python chat.py <IP_Adress> <Port> <Username> <Mode>`
*Note: on UNIX systems you may just run ./chat*

**IP_Adress** specifies the IP adress of server to connect, or to listen if you are the server.  
**Port** specifies the Port of server to connect, or to listen if you're the server.  
**Username** specifies your Username. It doesn't affect anything, but your appearence in chat.  
*Note: Username shouldn't be larger then 30 bytes. 1 Byte is 1 Symbol in ASCII, but in UTF symbols might be larger*
**Mode** specifies in which mode you run: Server(serv) or Client(clnt). Server listens on its own adress and Client connects to it, so Server should run first.  

You also should set up a Virtual Network to be able to connect to each other. (Radmin VPN or Hamachi will do it)

### Example

```
$ ./chat.py 127.0.0.1 3000 A97 serv
Waiting for client to connect..
Connection received from client on 127.0.0.1:44310. Exchanging session key.
Session key exchanged. Connection is secure.
Somebody: Hello, A97!
> Hello, Somebody!
Somebody: How are you doing there?
> Pretty fine.
Connection was Closed
```
```
$ ./chat.py 127.0.0.1 3000 Somebody clnt
Connecting to server..
Connected to server on 127.0.0.1:3000. Exchanging session key.
Session key exchanged. Connection is secure.
> Hello, A97!
A97: Hello, Somebody!
> How are you doing there?
A97: Pretty fine.
> ^CConnection was closed.
```

## Is that really secure?

Yes. It's using Elliptic Curve Diffie-Hellman Ephemeral(ECDHE) Algorithm for exchanging Session Key, HKDF-SHA256 diveration and AES256 for encrypting all messages.  
It is commonly used in websites.  

---

P.S. I made this project just for fun and education.
