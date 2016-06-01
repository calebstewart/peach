# -*- coding: utf-8 -*-
# @Author: Caleb Stewart
# @Date:   2016-05-31 19:29:59
# @Last Modified by:   Caleb Stewart
# @Last Modified time: 2016-05-31 19:55:14
from fuzz.fuzzer import Fuzzer
from pwn import *

class StdinFuzzer(Fuzzer):

	def __init__(self, ID, queue):
		super(StdinFuzzer, self).__init__(ID, queue)
		self.name = 'stdin fuzzer'

	def fuzz(self, target):
		for length in range(100, 1000, 100):
			yield ([], None, cyclic(length) + '\n', True) 