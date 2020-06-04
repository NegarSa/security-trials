#!/usr/bin/env python3
import socket
import pyaes
import hashlib


def init_connection(s):
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
    iv = "InitializationVe".encode('utf-8')
    return key.encode('utf-8'), iv


if __name__ == '__main__':

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('192.168.1.5', 8282))

        key_aes, iv = init_connection(s)

        while True:
            t_send = input()
            padding_len = 16 - (len(t_send) % 16)
            t_send = t_send + ' ' * padding_len

            s.sendall(pyaes.AESModeOfOperationCBC(key_aes, iv=iv)
                .encrypt(t_send.encode('utf-8')))

            print(pyaes.AESModeOfOperationCBC(key_aes, iv=iv)
                .decrypt(s.recv(1024)).decode())
