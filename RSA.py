import random
import math
import base64

DEBUG = False

first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
					31, 37, 41, 43, 47, 53, 59, 61, 67,
					71, 73, 79, 83, 89, 97, 101, 103,
					107, 109, 113, 127, 131, 137, 139,
					149, 151, 157, 163, 167, 173, 179,
					181, 191, 193, 197, 199, 211, 223,
					227, 229, 233, 239, 241, 251, 257,
					263, 269, 271, 277, 281, 283, 293,
					307, 311, 313, 317, 331, 337, 347, 349]

def get_bad_prime(num_length: int) -> int:
	while True:
		result = random.getrandbits(num_length)

		for divisor in first_primes_list:
			if result % divisor == 0 and divisor ** 2 <= result:
				break
			else:
				return result

def check_miller_rabin(num: int, trial_count: int = 20) -> bool:
	max_devisions_by_two = 0
	ec = num - 1
	while ec % 2 == 0:
		ec >>= 1
		max_devisions_by_two += 1
	assert(2**max_devisions_by_two * ec == num - 1)

	def trial_composite(round_tester):
		if pow(round_tester, ec, num) == 1:
			return False
		for i in range(max_devisions_by_two):
			if pow(round_tester, 2**i * ec, num) == num - 1:
				return False
		return True

	for i in range(trial_count):
		round_tester = random.randrange(2, num)
		if trial_composite(round_tester):
			return False
	return True

def get_prime(num_length: int) -> int:
	result = get_bad_prime(num_length)
	while not check_miller_rabin(result):
		result = get_bad_prime(num_length)

	return result

def gcd(a: int, b: int) -> int:
	if a == 0: return b
	if b == 0 or a == b: return a
	if a == 1 or b == 1: return 1

	both_odd = True
	even_num = 0

	if a % 2 == 0: 
		a >>= 1
		both_odd = False
		even_num += 1
	if b % 2 == 0:
		b >>= 1
		both_odd = False
		even_num += 1

	if both_odd:
		if a > b: return gcd((a - b) >> 1, b)
		if a < b: return gcd(a, (b - a) >> 1)
	else:
		return gcd(a, b) << (1 if even_num == 2 else 0)

def inverse(a: int, n: int) -> int:
	t = 0
	t_new = 1

	r = n
	r_new = a

	while r_new != 0:
		quotient = r // r_new
		(t, t_new) = (t_new, t - quotient * t_new)
		(r, r_new) = (r_new, r - quotient * r_new)

	if r > 1:
		return -1
	if t < 0:
		t = t + n

	return t

class Manager:
	def __init__(self, num_length: int = 1024):
		pass

	def generate_keys(self, num_length: int = 1024) -> ((int, int), (int, int)):
		if DEBUG: print("Generating keys...")

		d = 0
		while True:
			p = get_prime(num_length)

			if DEBUG: print(f"p = {p}")

			q = get_prime(num_length)
			if DEBUG: print(f"\ttrying q = {q}")
			while q == p:
				q = get_prime(num_length)
				if DEBUG: print(f"\ttrying q = {q}")

			if DEBUG: print(f"q = {q}")

			n = p * q

			if DEBUG: print(f"n = p * q = {n}")

			phi = (p - 1) * (q - 1)

			if DEBUG: print(f"phi = (p - 1) * (q - 1) = {phi}")

			e_values = [17, 257, 65537]
			e = e_values[random.randint(0, 2)]

			if DEBUG: print(f"e = {e}")

			d = inverse(e, phi)

			if d < 0: 
				if DEBUG: print("d < 0 - Starting over...")
			else:
				break

		if DEBUG: print(f"d = {d}")
		if DEBUG: print(f"e * d mod phi(n) = {e * d % n}")

		self.public_key  = (e, n)
		self.private_key = (d, p, q)
		self.mod = n

		if DEBUG: print(f"Keys are generated!\nPublic: {self.public_key}\nPrivate: {self.private_key}")

		return (self.public_key, self.private_key)


	def encode_key(self, key: list) -> bytes:
		result = b""
		for key_element in key:
			if DEBUG: print(f"key_element: {key_element}, size: {key_element.bit_length()}")
			result += key_element.to_bytes((key_element.bit_length() + 7) // 8, "big")
			result += b'\x00' * 16

		return base64.b64encode(result)

	def export_private_key(self) -> bytes:
		return self.encode_key(self.private_key)

	def export_public_key(self) -> bytes:
		return self.encode_key(self.public_key)

	def export_private_key_to_file(self, filename: str = "rsa_key"):
		file = open(filename, "wb")
		file.write(self.export_private_key())
		file.close()

	def export_public_key_to_file(self, filename: str = "rsa_key.pub"):
		file = open(filename, "wb")
		file.write(self.export_public_key())
		file.close()

	def export_keys(self, private_key_filename: str = "rsa_key", public_key_filename: str = "rsa_key.pub"):
		self.export_private_key_to_file(private_key_filename)
		self.export_public_key_to_file(public_key_filename)


	def decode_key(self, key: bytes) -> list:
		return list(map(int.from_bytes, base64.b64decode(key).split(b'\x00' * 16)[:-1]))

	def import_private_key(self, key: bytes):
		self.private_key = self.decode_key(key)
		self.mod = self.private_key[1] * self.private_key[2]

	def import_public_key(self, key: bytes):
		self.public_key = self.decode_key(key)
		self.mod = self.public_key[1]

	def import_private_key_from_file(self, filename: str = "rsa_key"):
		file = open(filename, "rb")
		self.import_private_key(file.read())
		file.close()

	def import_public_key_from_file(self, filename: str = "rsa_key.pub"):
		file = open(filename, "rb")
		self.import_public_key(file.read())
		file.close()

	def import_keys(self, private_key_filename: str = "rsa_key", public_key_filename: str = "rsa_key.pub"):
		self.import_private_key_from_file(private_key_filename)
		self.import_public_key_from_file(public_key_filename)

		if DEBUG: print(f"private key: {self.private_key}, public key: {self.public_key}, mod: {self.mod}")


	def encrypt_int(self, data: int) -> int:
		return pow(data, self.public_key[0], self.mod)

	def decrypt_int(self, data: int) -> int:
		return pow(data, self.private_key[0], self.mod)

	def sign_int(self, data: int) -> int:
		return self.decrypt_int(data)

	def check_int(self, data: int, sign: int) -> bool:
		return data == self.encrypt_int(sign)


	def encrypt(self, data: bytes) -> bytes:
		data_int = int.from_bytes(data, "big")

		result = self.encrypt_int(data_int)
		size = (result.bit_length() + 7) // 8

		#if DEBUG: print(f"ecnrypted data size: {size}")

		return result.to_bytes(size, "big")

	def decrypt(self, data: bytes) -> bytes:
		data_int = int.from_bytes(data, "big")

		result = self.decrypt_int(data_int)
		size = (result.bit_length() + 7) // 8 

		#if DEBUG: print(f"decrypted data size: {size}")

		return result.to_bytes(size, "big")

	def sign(self, data: bytes) -> bytes:
		return self.decrypt(data)

	def check(self, data: bytes, sign: bytes) -> bool:
		return data == self.encrypt(sign)

if DEBUG:
	rsa = Manager()
	#rsa.generate_keys()
	#rsa.export_keys()
	rsa.import_keys()
	while True:
		print("test: ", end="")
		data = input().encode()
		print("encrypt-decrypt test ", end="")
		print("passed!" if rsa.decrypt(rsa.encrypt(data)) == data else "failed")
		print(f"result: {rsa.decrypt(rsa.encrypt(data))}")
		print("sign-check test ", end="")
		print("passed!" if rsa.check(data, rsa.sign(data)) else "failed")
