import json
import numpy as np
from scipy.optimize import linear_sum_assignment
import tkinter as tk
from tkinter import filedialog
import os
from idaapi import get_input_file_path

class Funcs():
	def __init__(self, file_name):
		with open(file_name, 'r') as file:
			self.__dict = json.load(file)

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
	"""
	Класс "fuzzy" сравнения двух функций
	Создает матрицу, где каждый элемент отражает процент схожести двух условий
	"""
	def __init__(self, func1, func2):
		self.__name1 = func1[0]
		self.__name2 = func2[0]

		smol_dict = func1[1]
		self.__addr1 = smol_dict['address']
		self.__rows = smol_dict['constraints']

		smol_dict = func2[1]
		self.__addr2 = smol_dict['address']
		self.__cols = smol_dict['constraints']

		self.__fuzzTable(self.__rows, self.__cols)
		self.__total = self.__hungAlg()


	def __fuzzTable(self, constr1, constr2):
		"""
		Функция формирования таблицы(матрицы) коэффициентов

		:param constr1: Условия первой функции
		:param constr2: Условия второй функции
		:return: Таблица коэффициентов схожести каждого условия
		"""
		# Объявляем матрицу
		self.__table = np.zeros((len(constr1), len(constr2)))
		# mrtx = [[0 for j in range(len(constr2))] for i in range(len(constr1))]
		# Проходимся по всем элементам
		for i, con1 in enumerate(constr1):
			for j, con2 in enumerate(constr2):
				# Если сразу видно, что два условия идентичны, то не обязательно загонять их в функцию сравнения
				if con1 == con2:
					self.__table[i, j] = 1
					continue
				# Заполняем матрица
				self.__table[i, j] = self.__fuzz(con1, con2)

	def __fuzz(self, con1, con2):
		"""
		Функция сравнения двух отдельных условий

		:param con1: Условие из первой функции
		:param con2: Условие из второй функции
		:return: Коэффициент схожести двух условий
		"""

		# Разделяем условия по операциям сравнения. Если условие не разделимо, то оставляем его как список
		ops = [' != ', ' == ', ' >= ', ' > ', ' <= ', ' < ']
		sep1 = next((con1.split(op) for op in ops if op in con1), [con1])
		sep2 = next((con2.split(op) for op in ops if op in con2), [con2])

		# Если условия разная "длина", то предполагается, что они отличаются достаточно сильно,
		# чтобы не рассматривать их в даньнейшем
		if len(sep1) != len(sep2):
			return 0.000

		# Если у условий одинаковый оператор сравнения, то это сразу + к коэффициенту
		ratio = 0
		if any(op in con1 and op in con2 for op in ops):
			ratio = 1

		# Главный алгоритм сравнения
		for i in range(len(sep1)):
			# Находим одинаковые элементы в каждом кусочке двух условий
			extra_sep1, extra_sep2 = set(sep1[i].split()), set(sep2[i].split())
			m_ratio = len(extra_sep1 & extra_sep2)
			# Прибавляем к коэффициенту степень схожести элементов
			ratio += m_ratio/(max(len(extra_sep1), len(extra_sep2)))
		# Преобразуем коффициент к относительному
		res = ratio/(len(sep1) + 1)
		return res

	def __hungAlg(self):
		"""
		Алгоритм поиска назначений. Используется для того, чтобы сопоставить максимально подобные условия двух фукнций.

		:return: Коэффициент схожести двух функций
		"""
		neg_matrix = -self.__table
		row_ind, col_ind = linear_sum_assignment(neg_matrix)
		return -neg_matrix[row_ind, col_ind].sum()/max(neg_matrix.shape)

	def __str__(self):
		output = self.__name1 + ' x ' + self.__name2 + ':\n'
		# for row in self.__table:
		# 	for item in row:
		# 		output += "{:<8}".format(item)
		# 	output += '\n'
		output += "Total alikeness score: " + str(round(self.__total * 100, 2)) + '%\n'

		return output

	@property
	def rows(self):
		return self.__rows

	@property
	def cols(self):
		return self.__cols

	@property
	def name(self):
		return self.__name1 + ' x ' + self.__name2

	@property
	def total(self):
		return self.__total

def chooseFile():
	root = tk.Tk()
	root.withdraw()

	file_extension = '.json'

	file_path = filedialog.askopenfilename(filetypes=[(f"Файлы {file_extension}", f"*{file_extension}")])

	if file_path and os.path.splitext(file_path)[-1] == file_extension:
		return file_path
	else:
		return None

if __name__ == '__main__':
	file1 = get_input_file_path() + '.json'
	file2 = chooseFile()
	if file2 == None:
		raise Exception("Файл не выбран!")
	if file1 == file2:
		raise Exception("Один и тот же файл!")

	funcs1 = Funcs(file1)
	funcs2 = Funcs(file2)

	cmpList = list()

	for func1 in funcs1.items():
		for func2 in funcs2.items():
			len1 = len(func1[1]['constraints'])
			len2 = len(func2[1]['constraints'])

			# Если у функций нет условий, то их следует рассматривать по другим критериям
			if len1 == 0 and len2 == 0:
				mess = func1[0] + " and " + func2[0] + " needs another type of diffing"
				cmpList.append(mess)
				continue

			# Если у двух функций достаточно разное количество условий, то предполагается, что они достаточно разные
			if abs(len1 - len2)/max(len1, len2) > 0.6:
				mess = func1[0] + " and " + func2[0] + " are probably too different"
				cmpList.append(mess)
				continue

			# Все окей, можно составлять таблицу
			cmpList.append(FuzzyCmp(func1, func2))

	for cmp in cmpList:
		if type(cmp) != str:
			print(cmp)