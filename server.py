'''
import socket
import threading

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

def on_new_client(conn, addr):
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        conn.sendall(data)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(2)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=on_new_client, args=(conn, addr)).start()
            
'''

import DASS

dass = DASS.Server()