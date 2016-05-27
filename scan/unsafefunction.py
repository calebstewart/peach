# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:19:28
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-27 14:42:15
from scanner import Scanner
import subprocess
from pwn import *

class UnsafeFunctionBinaryScanner(Scanner):

	def __init__(self, target, file, queue):
		super(UnsafeFunctionBinaryScanner, self).__init__(target, file, queue)

	def scan(self):
		# Here we should look through the binary executable at self.target for
		# unsafe function usage.
		return

class UnsafeFunctionPythonScanner(Scanner):

	def __init__(self, target, file, queue):
		super(UnsafeFunctionPythonScanner, self).__init__(target, file, queue)

	def scan(self):
		# Here we should look through the script at self.target for
		# unsafe function usage.
		return

class UnsafeFunctionELFScanner(Scanner):

	# Just to name a few
	warningFunctions = [ 'system' ]

	def __init__(self, target, file, queue):
		super(UnsafeFunctionELFScanner, self).__init__(target, file, queue)

	def scan(self):
		# Here we should look through the script at self.target for
		# unsafe function usage.
		elf = None
		elf = ELF(self.target)
		for bad in self.warningFunctions:
			if bad in elf.symbols:
				self.hit('bad symbol \'%s\'' % bad, 'symbol table')
				# self.hit(Scanner.WARN, 'found bad symbol \'{0}\' in {1}!'.format(bad, self.target))
		return

	@staticmethod
	def match(scan, target):
		try:
			ELF(target)
		except:
			return False
		return True