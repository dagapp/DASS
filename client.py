import DASS
from peer import Peer

'''
print("Select port: ", end = '')
server_port = int(input())

peer = Peer("127.0.0.1", server_port)
peer.start()

print("Select port to connect: ", end = '')
connect_port = int(input())

peer.connect("127.0.0.1", connect_port)


print("Enter the message: ", end = '')
message = input()

peer.send("127.0.0.1", connect_port, message)

print(peer.recv())


while not peer.conn_recv_accepted: pass
'''

dass = DASS.Client()
dass.terminal_interact()