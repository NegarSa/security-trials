#!/usr/bin/env python3

import socket
import pyaes
import hashlib

def init_server():
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.bind(('192.168.1.5', 8282))
    s1.listen(1)
    s, addr = s1.accept()

    shared_prime = 17383
    shared_base = 5
    server_secret = 200
    A = (shared_base ** server_secret) % shared_prime
    s.sendall(str(A).encode('utf-8'))
    B = int(s.recv(2048).decode())
    key = (B ** server_secret) % shared_prime
    h = hashlib.sha256()
    h.update(str(key).encode('utf-8'))
    key = (h.hexdigest())[:32]
    return key.encode('utf-8'), s

def init_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.1.11', 8282))
    shared_prime = 17383
    shared_base = 5
    client_secret = 738
    B = (shared_base ** client_secret) % shared_prime
    A = int(s.recv(2048).decode())
    s.sendall(str(B).encode('utf-8'))
    key = (A ** client_secret) % shared_prime
    h = hashlib.sha256()
    h.update(str(key).encode('utf-8'))
    key = (h.hexdigest())[:32]
    return key.encode('utf-8'), s


if __name__ == '__main__':
    iv = "InitializationVe".encode('utf-8')
    key1, s1 = init_server()
    key2, s2 = init_client()

    text = pyaes.AESModeOfOperationCBC(key2, iv=iv)
                    .decrypt(s2.recv(1024)).decode()
    print('Received from client: ' + text)

    s1.sendall(pyaes.AESModeOfOperationCBC(key1, iv = iv)
                    .encrypt(text.encode('utf-8')))
    print('Sent to real server: ' + text)

    text = pyaes.AESModeOfOperationCBC(key1, iv=iv)
                    .decrypt(s1.recv(1024)).decode()
    print('Received from server: ' + text)

    s2.sendall(pyaes.AESModeOfOperationCBC(key2, iv = iv)
                    .encrypt(text.encode('utf-8')))
    print('Sent to real client: ' + text)
