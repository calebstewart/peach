# -*- coding: utf-8 -*-
# @Author: john
# @Date:   2016-05-27 08:42:28
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-29 17:27:35
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
			'from\s*%s\s*import\s*([A-Za-z,*]*)',
			'import\s*([A-Za-z]*)?(,?)(\s)?%s([A-Za-z,]*)?(,?)(\s)?',
		]
		# Define the patterns RegexScanner will use
		self.patterns = [
			{
				'name': '{0}',
				're': re.compile(flare % dangerous_modules)
			} for flare in regex_flares
		]