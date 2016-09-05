# -*- coding: utf-8 -*-
# @Author: Caleb Stewart
# @Date:   2016-05-31 19:29:59
# @Last Modified by:   Caleb Stewart
# @Last Modified time: 2016-05-31 19:55:14
from fuzz.fuzzer import Fuzzer
from pwn import *
import itertools

class GenericXPlatformFuzzer(Fuzzer):

	def __init__(self, ID, queue):
		super(GenericXPlatformFuzzer, self).__init__(ID, queue)
		self.name = 'generic xplatform input fuzzer'
		# Read in the format string attacks
		f = open('./fuzz/fuzzdb/attack/all-attacks/all-attacks-xplatform.txt')
		self.attacks = f.read().strip().split('\n')
		self.count = len(self.attacks)
		f.close()

	def fuzz(self, target):
		for item in self.attacks:
			yield([], None, '\n'.join(item) + '\n', True)