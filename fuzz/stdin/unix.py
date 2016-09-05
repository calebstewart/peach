# -*- coding: utf-8 -*-
# @Author: Caleb Stewart
# @Date:   2016-05-31 19:29:59
# @Last Modified by:   Caleb Stewart
# @Last Modified time: 2016-05-31 19:55:14
from fuzz.fuzzer import Fuzzer
from pwn import *
import itertools

class GenericUnixFuzzer(Fuzzer):

	def __init__(self, ID, queue):
		super(GenericUnixFuzzer, self).__init__(ID, queue)
		self.name = 'generic unix input fuzzer'
		# Read in the format string attacks
		f = open('./fuzz/fuzzdb/attack/all-attacks/all-attacks-unix.txt')
		self.attacks = f.read().strip().split('\n')
		self.count = len(self.attacks)
		f.close()

	def fuzz(self, target):
		for item in self.attacks:
			yield([], None, '\n'.join(item) + '\n', True)