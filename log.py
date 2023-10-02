from datetime import datetime

class Log:
	def __init__(self, print_threshold = 3, filename = "log"):
		self.file = open(filename, "a")
		self.print_threshold = print_threshold

	def record(self, record_type, record_code, record_text):
		prefix = '['

		if record_type == 1:
			prefix += "INF"
		elif record_type == 2:
			prefix += "WAR"
		elif record_type == 3:
			prefix += "ERR"

		prefix += ' ' + f"{record_code:#0{4}x}" + ']: '

		record_text = datetime.now().strftime("%Y.%m.%d %H:%M:%S.%f") + ' ' + prefix + record_text

		self.file.write(record_text + '\n')

		if record_type >= self.print_threshold:
			print(record_text)

	def info(self, record_code, record_text):
		self.record(1, record_code, record_text)

	def warning(self, record_code, record_text):
		self.record(2, record_code, record_text)

	def error(self, record_code, record_text):
		self.record(3, record_code, record_text)