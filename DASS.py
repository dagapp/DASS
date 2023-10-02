import socket
import RSA
from pathlib import Path
import threading
import random
from log import Log
import time
import struct
from peer import Peer

LOG = True
DEBUG = True

LENGTH_NAME      = 16
LENGTH_CHECK_SEQ = 32
LENGTH_DEFAULT_PADD = 4
LENGTH_SIGN_PADD = LENGTH_DEFAULT_PADD
LENGTH_CODE      = 4
LENGTH_MESSAGE   = 1024

BYTE_DEFAULT_PADD = b'\x00'
BYTE_SIGN_PADD = BYTE_DEFAULT_PADD
BYTE_NAME_PADD = BYTE_DEFAULT_PADD

CODE_CREATE_CLIENT = b"\xca\xfe\xba\xbe"
CODE_GET_KEY       = b"\x63\x77\xf0\x0d"
CODE_BAD_NAME      = b"\xba\xad\xba\xbe"
CODE_AUTH_FAILED   = b"\xba\xad\xf0\x0d"

DEFAULT_ADDR = "127.0.0.1"
DEFAULT_PORT = 65432
DEFAULT_PRIVATE_KEY_FILENAME = "rsa_key"
DEFAULT_PUBLIC_KEY_FILENAME  = "rsa_key.pub"
DEFAULT_LOG_FILENAME = "log"
DEFAULT_PADD = LENGTH_DEFAULT_PADD * BYTE_DEFAULT_PADD

LIFETIME_KEY = 1 * 3600 

log = Log(1)

def get_padded_name(name: str) -> bytes:
	name_hex = name.encode()
	return (LENGTH_NAME - len(name_hex)) * BYTE_NAME_PADD + name_hex

class Server:
	def __init__(self, 
				addr = DEFAULT_ADDR,
				port = DEFAULT_PORT,
				private_key_filename = DEFAULT_PRIVATE_KEY_FILENAME, 
				public_key_filename = DEFAULT_PUBLIC_KEY_FILENAME):

		log.info(0x00, f"Starting server on {addr}:{port}...")

		#Creating an RSA manager object for server and clients dict for RSA managers
		log.info(0x01, "Creating an RSA manager objects...")

		self.rsa_server  = RSA.Manager()
		self.rsa_clients = {}

		private_key_file = Path(private_key_filename)
		public_key_file  = Path(public_key_filename)

		if private_key_file.is_file() and public_key_file.is_file():
			log.info(0x02, f"Importing keys from {private_key_filename} and {public_key_filename}")
			self.rsa_server.import_keys(private_key_filename, public_key_filename)
			log.info(0xFF, "Success!")
		else:
			log.info(0x03, f"Generating keys...")
			self.rsa_server.generate_keys()
			log.info(0xFF, "Success!")

			log.info(0x04, f"Exporting keys to a file")
			self.rsa_server.export_keys(private_key_filename, public_key_filename)
			log.info(0xFF, "Success!")

		log.info(0x05, f"Public key: {self.rsa_server.export_public_key()}")
		log.info(0xFF, "Success!")

		#Creating server socket
		log.info(0x06, f"Creating server socket on {addr}:{port}...")

		self.socket_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
		self.socket_listen.bind((addr, port))
		self.socket_listen.listen()

		log.info(0xFF, "Success!")

		while True:
			conn, clients_addr = self.socket_listen.accept()
			log.info(0x10, f"Connected client: {clients_addr}")
			threading.Thread(target=self.handle_client, args=(conn, addr)).start()

	def handle_client(self, conn, addr):
		while True:
			data = None
			while not data: data = conn.recv(LENGTH_MESSAGE)

			# Get clients public key and send self public key
			if data[:LENGTH_CODE] == CODE_CREATE_CLIENT:
				self.create_client(conn, data[LENGTH_CODE:])

			# Provide client with other client's public key
			elif data[:LENGTH_CODE] == CODE_GET_KEY:
				self.provide_client_key(conn, data[LENGTH_CODE:])

	def create_client(self, conn, data):
		log.info(0x11, f"Creating new client...")

		client_name = data[:LENGTH_NAME]

		log.info(0x12, f"Client's name: {client_name}")

		#Check if client already exists
		if client_name in self.rsa_clients:
			log.error(0x10, "Client already exists! Exiting...")
			conn.sendall(CODE_BAD_NAME)
			return

		client_public_key = data[LENGTH_NAME:]

		log.info(0x13, f"Client's public key: {client_public_key}")

		#Create an RSA manager object for a client
		log.info(0x14, "Creting client's RSA manager objects...")
		self.rsa_clients[client_name] = RSA.Manager()
		self.rsa_clients[client_name].import_public_key(client_public_key)
		log.info(0xFF, "Success!")

		#Authenticate client
		log.info(0x15, "Authenticating client...")

		check_seq_int = random.getrandbits(LENGTH_CHECK_SEQ)
		check_seq = check_seq_int.to_bytes((check_seq_int.bit_length() + 7) // 8, "big")

		log.info(0x16, f"Check sequence: {check_seq}")

		check_seq_enc = self.rsa_clients[client_name].encrypt(check_seq)

		log.info(0x17, f"Encrypted check sequence: {check_seq_enc}")

		conn.sendall(check_seq_enc)

		recv_check_seq = None
		while not recv_check_seq: recv_check_seq = conn.recv(LENGTH_MESSAGE)

		log.info(0x18, f"Checking recieved decrypted check sequence...")
		if check_seq != recv_check_seq:
			log.error(0x11, "Check sequence failed! Exiting...")
			conn.sendall(CODE_AUTH_FAILED)
			return
		log.info(0xFF, "Success!")

		#Send public key to a client
		log.info(0x19, "Sending public key...")
		conn.sendall(self.rsa_server.export_public_key())
		log.info(0xFF, "Success!")

	def provide_client_key(self, conn, data):
		log.info(0x1A, "Providing client public key...")
		client_name = data

		#Check if client exists
		log.info(0x1B, "Checking if client exists...")
		if client_name not in self.rsa_clients:
			log.error(0x12, "Client doesn't exist! Exiting...")
			conn.sendall(CODE_BAD_NAME)
			return
		log.info(0xFF, "Success!")

		#Send signed clients name and public key
		log.info(0x1C, "Sending signed client name and public key...")

		message = client_name + self.rsa_clients[client_name].export_public_key()
		sign = self.rsa_server.sign(message)

		message += DEFAULT_PADD + sign

		log.info(0x1D, f"Message: {message}")

		conn.sendall(message)

		log.info(0x1D, "Success!")


class Client:
	def __init__(self, 
				private_key_filename = DEFAULT_PRIVATE_KEY_FILENAME, 
				public_key_filename  = DEFAULT_PUBLIC_KEY_FILENAME,
				log_filename = DEFAULT_LOG_FILENAME):

		log.info(0x20, "Starting client...")

		#Creating RSA manager objects for client and server
		log.info(0x21, "Creating RSA manager objects...")

		self.rsa_server = RSA.Manager()
		self.rsa_client = RSA.Manager()

		self.import_keys(private_key_filename, public_key_filename)

		log.info(0x25, f"Public key: {self.rsa_client.export_public_key()}")
		log.info(0xFF, "Success!")

	def import_keys(self, private_key_filename, public_key_filename):
		private_key_file = Path(private_key_filename)
		public_key_file  = Path(public_key_filename)

		if private_key_file.is_file() and public_key_file.is_file(): 
			log.info(0x22, f"Importing keys from {private_key_filename} and {public_key_filename}")
			self.rsa_client.import_keys(private_key_filename, public_key_filename)
			log.info(0xFF, "Success!")
		else:
			log.error(0x20, "Files do not exist! Generating new keys...")

			log.info(0x23, f"Generating keys...")
			self.rsa_client.generate_keys()
			log.info(0xFF, "Success!")

			log.info(0x24, f"Exporting keys to files (private: {private_key_filename}, public: {public_key_filename})")
			self.rsa_client.export_keys(private_key_filename, public_key_filename)
			log.info(0xFF, "Success!")

	def connect_server(self, name, addr = DEFAULT_ADDR, port = DEFAULT_PORT):
		log.info(0x30, "Connecting to a server...")

		#Creating a server socket
		log.info(0x31, "Creating a server socket...")

		self.socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket_server.connect((addr, port))

		log.info(0xFF, "Success!")

		#Constructing and sending a CREATE_CLIENT message
		log.info(0x32, "Sending a CREATE_CLIENT message")

		name_hex = get_padded_name(name)
		message = CODE_CREATE_CLIENT + name_hex + self.rsa_client.export_public_key()

		log.info(0x33, f"Message: {message}")

		self.socket_server.sendall(message)

		log.info(0xFF, "Success!")

		#Authenticate on server
		log.info(0x34, "Authenticating on server...")

		reply = None
		while not reply: reply = self.socket_server.recv(LENGTH_MESSAGE)

		if reply[:LENGTH_CODE] == CODE_BAD_NAME:
			log.error(0x30, f"Client name \"{name}\" is already taken! Exiting...")
			return

		check_seq_enc = reply

		log.info(0x35, f"Encrypted check sequence: {check_seq_enc}")

		check_seq = self.rsa_client.decrypt(check_seq_enc)

		log.info(0x36, f"Decrypted check sequence: {check_seq}")

		log.info(0x37, "Sending...")

		self.socket_server.sendall(check_seq)

		log.info(0xFF, "Success!")

		#Saving a server public key
		log.info(0x38, "Recieving a server's public key...")

		reply = None
		while not reply: reply = self.socket_server.recv(LENGTH_MESSAGE)

		if reply[:LENGTH_CODE] == CODE_AUTH_FAILED:
			log.error(0x31, f"Authentication failed!Exiting...")

		self.rsa_server.import_public_key(reply)

		log.info(0x39, f"Server's public key: {self.rsa_server.export_public_key()}")

		log.info(0xFF, "Success!")
		log.info(0xFF, "Success!")

	def establish_secret_key(self, name, conn_send, conn_recv):
		log.info(0x40, f"Establishing a secret key with {name}")

		log.info(0x41, "Sending opponent's name to a server...")
		name_hex = get_padded_name(name)
		self.socket_server.sendall(CODE_GET_KEY + name_hex)
		log.info(0xFF, "Success!")

		log.info(0x42, "Recieving signed name and public key of the opponent...")

		reply = None
		while not reply: reply = self.socket_server.recv(LENGTH_MESSAGE)

		if reply[:LENGTH_CODE] == CODE_BAD_NAME:
			log.error(0x40, f"Client with name {name} does not exist! Exiting...")
			return
		log.info(0xFF, "Success!")

		log.info(0x43, "Checking recieved reply signature...")
		reply_split = reply.split(DEFAULT_PADD)

		reply_data = reply_split[0]
		reply_sign = reply_split[1]

		log.info(0x44, f"Data: {reply_data}, Signature: {reply_sign}")

		if not self.rsa_server.check(reply_data, reply_sign):
			log.error(0x41, "Incorrect signature! Exiting...")
			return
		log.info(0xFF, "Success!")

		recv_name = reply_data[LENGTH_CODE:LENGTH_CODE + LENGTH_NAME]
		recv_public_key = reply_data[LENGTH_CODE + LENGTH_NAME:]

		log.info(0x45, "Checking reply opponent's name...")
		if name_hex != recv_name:
			log.error(0x42, "Incorrect reply name! Exiting...")
			return
		log.info(0xFF, "Success!")

		log.info(0x46, "Creating an RSA manager objects for opponent...")
		self.rsa_opponent = RSA.Manager()
		self.rsa_opponent.import_public_key(recv_public_key)
		log.info(0xFF, "Success!")

		log.info(0x47, "Creating a thread for parallel ESTABLISH_SECRET_KEY message calculation...")
		#possible proccess solution
		threading.Thread(target=send_init_message, args=(name, conn_send, conn_recv)).start()
		log.info(0xFF, "Success!")
		
		log.info(0x48, "Listening for ESTABLISH_SECRET_KEY message from the opponent...")
		recv = None
		while not recv: recv = conn_recv.recv(LENGTH_MESSAGE)
		log.ingo(0x49, "ESTABLISH_SECRET_KEY message recieved!")

		self.stop_init_calc = True

		'''
		session_keys = rsa_session.export_private_key() + DEFAULT_PADD + rsa_session.export_public_key()

		lifetime_name_session_key = key_lifetime + DEFAULT_PADD + name_hex + session_keys

		message = timestamp_enc + DEFAULT_PADD + 
					 lifetime_name_session_key + DEFAULT_PADD + 
					 lifetime_name_session_key_sign + DEFAULT_PADD + 
					 secret_key_enc + DEFAULT_PADD + 
					 secret_key_enc_sign
		'''

		recv_split = recv.split(DEFAULT_PADD)

		timestamp_enc = recv_split[0]
		# TODO decrypt
		timestamp = timestamp_enc

		lifetime_name_session_key      = recv_split[1]
		lifetime_name_session_key_sign = recv_split[2]

		log.info(0x4A, "Checking lifetime, name, session signature...")
		if not self.rsa_opponent.check(lifetime_name_session_key, lifetime_name_session_key_sign):
			log.error(0x43, "Incorrect signature! Exiting...")
			return
		log.info(0xFF, "Success!")

		lifetime_name_session_key_split = lifetime_name_session_key.split(DEFAULT_PADD)
		recv_lifetime     = lifetime_name_session_key_split[0]
		recv_name         = lifetime_name_session_key_split[1]

		log.info(0x4B, "Checking recieved name...")
		if recv_name != name:
			log.error(0x44, "Incorrect recieved name! Exiting...")
			return
		log.info(0xFF, "Success!")

		recv_session_keys = lifetime_name_session_key_split[2]

		recv_session_keys_split = recv_session_keys.split(DEFAULT_PADD)

		recv_session_private_key = recv_session_keys_split[0]
		recv_session_public_key  = recv_session_keys_split[1]

		log.info(0x4C, "Creating RSA manager object for session keys and importing recieved keys...")
		rsa_session = RSA.Manager()
		rsa_session.import_private_key(recv_session_private_key)
		rsa_session.import_public_key(recv_session_public_key)
		log.info(0xFF, "Success!")
		
		secret_key_enc = recv_split[3]
		secret_key_enc_sign = recv_split[4]

		log.info(0x4D, "Checking encrypted secret key signature...")
		if not rsa_session.check(secret_key_enc, secret_key_enc_sign):
			log.error(0x45, "Incorrect signature! Exiting...")
			return
		log.info(0xFF, "Success!")

		log.info(0x4E, "Decrypting secret_key...")
		secret_key = self.rsa_client.decrypt(secret_key_enc)
		log.info(0xFF, "Success!")

		log.info(0x4F, "Sending final secret encrypted timestamp message...")
		timestamp = time.time()
		#timestamp_enc = self.rsa_client.encrypt(struct.pack("!f", timestamp))
		timestamp_enc = timestamp

		conn_send.sendall(timestamp_enc)
		log.info(0xFF, "Success!")

	def check_if_init_recv(self):
		if self.stop_init_calc:
			log.info(0xFE, "ESTABLISH_SECRET_KEY message has been recieved from the opponent. Thread exiting...")
			return True

		return False

	def send_init_message(self, name, conn_send, conn_recv):
		log.info(0x46, "Calculating encrypted timestamp, self signed lifetime, self name, session key and session signed opponent encrypted secret key...")

		timestamp = time.time()
		#timestamp_enc = self.rsa_client.encrypt(struct.pack("!f", timestamp))
		timestamp_enc = timestamp

		log.info(0x47, f"Timestamp: {timestamp}")


		if self.check_if_init_recv(): return



		key_lifetime_int = LIFETIME_KEY
		key_lifetime = key_lifetime_int.to_bytes((key_lifetime_int.bit_length() + 7) // 8, "big")

		log.info(0x48, f"lifetime: {key_lifetime_int}")
		
		name_hex = get_padded_name(name)

		log.info(0x49, f"Name: {name}")


		if self.check_if_init_recv(): return


		rsa_session = RSA.Manager()
		rsa_session.generate_keys()

		session_keys = rsa_session.export_private_key() + DEFAULT_PADD + rsa_session.export_public_key()


		if self.check_if_init_recv(): return


		log.info(0x4A, f"Session keys: {session_keys}")

		lifetime_name_session_key = key_lifetime + DEFAULT_PADD + name_hex + session_keys
		lifetime_name_session_key_sign = rsa_client.sign(lifetime_name_session_key)


		if self.check_if_init_recv(): return


		secret_key_int = int.getrandbits(1024)
		secret_key = secret_key_int.to_bytes((secret_key_int.bit_length() + 7) // 8, "big")

		secret_key_enc = rsa_opponent.encrypt(secret_key)
		secret_key_enc_sign = rsa_session.sign(secret_key_enc)

		log.info(0x4B, f"Encrypted secret key: {secret_key_enc}")


		if self.check_if_init_recv(): return


		message = timestamp_enc + DEFAULT_PADD + lifetime_name_session_key + DEFAULT_PADD + lifetime_name_session_key_sign + DEFAULT_PADD + secret_key_enc + DEFAULT_PADD + secret_key_enc_sign


		if self.check_if_init_recv(): return


		log.info(0x4C, f"Sending ESTABLISH_SECRET_KEY message: {message}")

		self.conn_send.sendall(message)


		log.info(0x4D, "Recieving encrypted timestamp from opponent...")
		reply = None
		while not reply: reply = self.conn_recv.recv(LENGTH_MESSAGE)
		log.info(0xFF, "Success!")

		log.info(0x4E, f"Encrypted timestamp: {reply}")


	def terminal_interact(self):
		print("Welcome to DASS Client!")

		while True:
			print("\nChoose an action:")
			print("1. Import keys")
			print("2. Connect to server")
			print("3. Establish a secret key with other client <- default")
			print("\nYour choice: ", end='')

			choice = input()[0]

			print()

			if choice == '1':
				print("Do you want to use dafault key files? (Y/n): ", end = '')
				choice = input()[0]

				private_key_filename = "rsa_key"
				public_key_filename  = "rsa_key.pub"

				if choice == 'n':
					print("Enter private key filename: ", end = '')
					private_key_filename = input()

					print("Enter public key filename: ", end = '')
					public_key_filename = input()

				self.import_keys(private_key_filename, public_key_filename)

			elif choice == '2':
				print("Do you want to use default localhost server? (Y/n): ", end = '')
				choice = input()[0]

				if choice == 'n':
					print("Enter DASS server's address and port (addr port): ", end = '')
					addr_port_split = input().split(' ')

					addr = addr_port_split[0]
					port = int(addr_port_split[1])
				else:
					addr = "127.0.0.1"
					port = 65432

				print("Enter you name: ", end = '')
				name = input()

				self.connect_server(name, addr, port)
			else:
				print("Enter your server's socket port: ", end = '')
				server_port = int(input())

				peer = Peer("127.0.0.1", server_port)
				peer.start()

				print("Enter yout opponent's addr and port (addr port)", end = '')
				opponent_addr_port_split = input().split(' ')
				opponent_addr = opponent_addr_port_split[0]
				opponent_port = int(opponent_addr_port_split[1])

				peer.connect(opponent_addr, opponent_port)

				while not peer.conn_recv_accepted: pass

				print("Enter your opponent's DASS server name: ", end = '')

				name = input()

				self.establish_secret_key(name, peer.conns[("127.0.0.1", opponent_port)], peer.conn_recv)

				print("Secret key is established!")
