import json

file1 = r"C:\Sasha\Project1\x64\Debug\Project1.exe.json"
file2 = r"C:\Sasha\Project1\x64\Release\Project1.exe.json"

class Funcs():
	def __init__(self, file_name):
		with open(file_name, 'r') as file:
			self.__dict = json.load(file)

	# @property
	# def dict(self):
	#     return self.__dict.items()

	def __getitem__(self, key):
		return self.__dict[key]

	def __len__(self):
		return len(self.__dict)

	def keys(self):
		return self.__dict.keys()

	def values(self):
		return self.__dict.values()

	def items(self):
		return self.__dict.items()

###########################################
class FuzzyCmp():
	def __init__(self, func1, func2):
		self.__name1 = func1[0]
		self.__name2 = func2[0]
		# print(f"For {self.__name1} and {self.__name2}:")
		# print(f"For {func1[1]} and {func2[1]}:")
		self.__table = self.__fuzzTable(func1[1], func2[1])
		for i in self.__table:
			print(*i)

	# TODO: Why fuzzTable return 0s

	def __fuzzTable(self, constr1, constr2):
		mrtx = [[0] * len(constr2)] * len(constr1)
		for i, con1 in enumerate(constr1):
			for j, con2 in enumerate(constr2):
				if con1 == con2:
					mrtx[i][j] = 1
					continue
				mrtx[i][j] = self.__fuzz(con1, con2)
			# 	print(mrtx[i][j], end = ' ')
			# print()
		return mrtx

	def __fuzz(self, con1, con2):
		print(con1)
		print(con2)
		ops = [' != ', ' == ', ' >= ', ' > ', ' <= ', ' < ']
		sep1 = next((con1.split(op) for op in ops if op in con1), [con1])
		sep2 = next((con2.split(op) for op in ops if op in con2), [con2])

		print(f"\t{sep1}")
		print(f"\t{sep2}")

		ratio = 0
		if any(op in con1 and op in con2 for op in ops):
			ratio = 1

		# print(f"\tsep1: {sep1}")
		# print(f"\tsep2: {sep2}")

		if len(sep1) != len(sep2):
			return 0

		for i in range(len(sep1)):
			main, secondary = (sep1[i], sep2[i].split()) if sep1[i].count(' ') >= sep2[i].count(' ') else (sep2[i], sep1[i].split())
			# print(f"\t\tmain: {main}")
			# print(f"\t\tsecondary: {secondary}")
			m_ratio = 0
			for sec in secondary:
				# print(f"\t\t\tsec: {sec}")
				if sec in main:
					m_ratio += 1
					# print("\t\t\tIs in")
			ratio += m_ratio/(main.count(' ') + 1)
			print(f"\t\tratio: {ratio}")
		print(f"\tlen: {len(sep1) + 1}")
		print(f"\t{ratio/(len(sep1) + 1)}")
		return ratio/(len(sep1) + 1)


if __name__ == '__main__':
	funcs1 = Funcs(file1)
	funcs2 = Funcs(file2)

	cmpList = list()
	flag = 0
	for func1 in funcs1.items():
		for func2 in funcs2.items():
			if len(func1[1]) == 0 or len(func2[1]) == 0:
				if len(func1[1]) == 0 and len(func2[1]) == 0:
					mess = func1[0] + " and " + func2[0] + " are 'empty'!"
					cmpList.append(mess)
				print(f"skip {func1[0]} and {func2[0]}")
				continue
			cmpList.append(FuzzyCmp(func1, func2))
			flag = 1
			break
		if flag:
			break