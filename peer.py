import socket
import threading

class Peer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn_recv_accepted = False
        self.conns = {}

    def connect(self, peer_host, peer_port):
        try:
            conn_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn_send.connect((peer_host, peer_port))
            self.conns[(peer_host, peer_port)] = conn_send

            print(f"Connected to {peer_host}:{peer_port}")

        except socket.error as e:
            print(f"Failed to connect to {peer_host}:{peer_port}. Error: {e}")

    def listen(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)
        print(f"Listening for connections on {self.host}:{self.port}")

        while True:
            self.conn_recv, addr = self.socket.accept()
            self.conn_recv_accepted = True
            #self.connections.append(connection)
            print(f"Accepted connection from {addr}")

    def send(self, host, port, data):
        try:
            self.conns[(host, port)].sendall(data.encode())
        except:
            print(f"Failed to send data")

    def recv(self):
        try:
            return self.conn_recv.recv(1024)
        except socket.error as e:
            print(f"Failed to recieve data on server socket. Error: {e}")

    def start(self):
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()