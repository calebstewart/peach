# -*- coding: utf-8 -*-
# @Author: Caleb Stewart
# @Date:   2016-06-01 10:49:24
# @Last Modified by:   Caleb Stewart
# @Last Modified time: 2016-06-01 11:13:06
from scan.scanner import Scanner
from pwn import *

class ElfScanner(Scanner):

	def __init__(self, scannerId, mesgQueue):
		super(ElfScanner, self).__init__(scannerId, mesgQueue)
		self.name = 'elf scanner'
		self.bad_funcs = [ 'system', 'gets' ]

	def scan(self, target):
		elf = ELF(target)
		for f in self.bad_funcs:
			if f in elf.symbols:
				self.hit('call to dangerous function `{0}`'.format(f), hex(elf.symbols[f]))

	def match(self, target):
		try:
			ELF(target)
		except:
			return False
		return True