#!/usr/bin/env python3

import socket
import pyaes

HOST = '127.0.0.1'  
PORT = 8282      

key = "This_key_for_demo_purposes_only!"

iv = "InitializationVe"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)

        aes_e = pyaes.AESModeOfOperationCBC(key.encode('utf-8'), iv = iv.encode('utf-8'))

        t_send = 'Hello!FromServer'
        ciphertext = aes_e.encrypt(t_send.encode('utf-8'))

        
        while True:
            
            data = conn.recv(1024)
            aes_d = pyaes.AESModeOfOperationCBC(key.encode('utf-8'), iv = iv.encode('utf-8'))
            decrypted = aes_d.decrypt(data)
            print(str(decrypted))

            if not data:
                break
            conn.sendall(data)

