#!/usr/bin/env python3

import socket


HOST = '127.0.0.1'  
PORT = 8285


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    while True:

        t_send = input()

        s.sendall(t_send.encode('utf-8'))

        data = s.recv(1024)

        print('Received', str(data))

