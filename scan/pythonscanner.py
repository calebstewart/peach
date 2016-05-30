# -*- coding: utf-8 -*-
# @Author: john
# @Date:   2016-05-27 08:42:28
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-30 12:39:27
from regexscanner import RegexScanner
import re

class ModuleScanner(RegexScanner):
	
	# Nothing needs to be done here, but you can initialize any object data
	# you wish to use later on!
	def __init__(self, scannerId, mesgQueue):
		super(ModuleScanner, self).__init__(scannerId, mesgQueue)

		self.name = 'python import scanner'

		# Setup match criteria
		self.extensions = [ '.py' ]

		# I note this in a separate variable because they are used in
		# each regex
		dangerous_modules = '(__os__|os|subprocess|sh|commands|fabric|paramiko|pickle)'
		regex_flares = [
			# Why have all those groups in the regex? They complicate
			# the output when referencing subgroups...
			# 'from\s*%s\s*import\s*([A-Za-z,*]*)',
			# 'import\s*([A-Za-z]*)?(,?)(\s)?%s([A-Za-z,]*)?(,?)(\s)?',
			# Just use one group for the important part (the module
			# we are looking for).
			'from\s*%s\s*import\s*[A-Za-z,*]*',
			'import\s*[A-Za-z]*?,?\s?%s[A-Za-z,]*?,?\s?',
		]
		# Define the patterns RegexScanner will use
		self.patterns = [
			{
				'name': 'importing unsafe module \'{1}\'',
				're': re.compile(flare % dangerous_modules)
			} for flare in regex_flares
		]

class FunctionScanner(RegexScanner):

	def __init__(self, scannerId, mesgQueue):
		super(FunctionScanner, self).__init__(scannerId, mesgQueue)

		self.name = 'python function call scanner'

		self.extensions = [ '.py' ]

		self.patterns = [
			{
				'name': 'call to unsafe function \'{1}\'',
				're': re.compile(r'.*(system)\(.*\).*')
			}
		]