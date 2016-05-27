# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:19:28
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-27 01:52:19
import scanner
from pwn import *

class UnsafeFunctionBinaryScanner(scanner.Scanner):

	def __init__(self, target, file, queue):
		super(UnsafeFunctionBinaryScanner, self).__init__(target, file, queue)

	def scan(self):
		# Here we should look through the binary executable at self.target for
		# unsafe function usage.
		return

class UnsafeFunctionPythonScanner(scanner.Scanner):

	def __init__(self, target, file, queue):
		super(UnsafeFunctionPythonScanner, self).__init__(target, file, queue)

	def scan(self):
		# Here we should look through the script at self.target for
		# unsafe function usage.
		return
