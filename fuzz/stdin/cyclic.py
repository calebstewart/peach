# -*- coding: utf-8 -*-
# @Author: Caleb Stewart
# @Date:   2016-05-31 19:29:59
# @Last Modified by:   Caleb Stewart
# @Last Modified time: 2016-05-31 19:55:14
from fuzz.fuzzer import Fuzzer
from pwn import *

class CyclicFuzzer(Fuzzer):

	def __init__(self, ID, queue):
		super(CyclicFuzzer, self).__init__(ID, queue)
		self.name = 'cyclic input fuzzer'
		self.count = len(range(100,1100,100))

	def fuzz(self, target):
		for length in range(100, 1100, 100):
			yield ([], None, cyclic(length) + '\n', True) 