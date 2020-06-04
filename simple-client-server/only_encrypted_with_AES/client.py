#!/usr/bin/env python3

import socket
import pyaes

HOST = '127.0.0.1'  
PORT = 8282

key = "This_key_for_demo_purposes_only!"

iv = "InitializationVe"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    while True:

        t_send = input()

        aes_e = pyaes.AESModeOfOperationCBC(key.encode('utf-8'), iv = iv.encode('utf-8'))

        ciphertext = aes_e.encrypt(t_send.encode('utf-8'))

        s.sendall(ciphertext)

        data = s.recv(1024)

        aes_d = pyaes.AESModeOfOperationCBC(key.encode('utf-8'), iv = iv.encode('utf-8'))
        decrypted = aes_d.decrypt(data)

        print('Received', str(decrypted))

