#!/usr/bin/env python3

import socket
import pyaes
import hashlib


def init_connection(s):
    shared_prime = 17383
    shared_base = 5
    server_secret = 383
    A = (shared_base ** server_secret) % shared_prime
    s.sendall(str(A).encode('utf-8'))
    B = int(s.recv(2048).decode())
    key = (B ** server_secret) % shared_prime
    h = hashlib.sha256()
    h.update(str(key).encode('utf-8'))
    key = (h.hexdigest())[:32]
    iv = "InitializationVe".encode('utf-8')
    return key.encode('utf-8'), iv


if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
        s1.bind(('192.168.1.5', 8282))
        s1.listen(1)

        s, addr = s1.accept()
        with s:
            key_aes, iv = init_connection(s)

            while True:
                # Receive data and decrypt
                print(pyaes.AESModeOfOperationCBC(key_aes, iv=iv)
                    .decrypt(s.recv(1024)).decode())

                # Input data, encrypt and send
                t_send = input()
                padding_len = 16 - (len(t_send) % 16)
                t_send = t_send + ' ' * padding_len

                s.sendall(pyaes.AESModeOfOperationCBC(key_aes, iv=iv)
                    .encrypt(t_send.encode('utf-8')))
