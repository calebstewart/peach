# -*- coding: utf-8 -*-
# @Author: john
# @Date:   2016-05-27 08:42:28
# @Last Modified by:   John Hammond
# @Last Modified time: 2016-05-27 09:51:11
import scanner
import re
from pwn import *
# This package has color automatically, inherited from the top-level module

class ScanPythonModules(scanner.Scanner):
	
	# Nothing needs to be done here, but you can initialize any object data
	# you wish to use later on!
	def __init__(self, target, file, queue):
		super(ScanPythonModules, self).__init__(target, file, queue)

		# I note this in a separate variable because they are used in
		# each regex
		dangerous_modules = '(__os__|os|subprocess|sh|commands|fabric|paramiko|pickle)'


		self.regex_flares = [
			
			'from\s*%s\s*import\s*([A-Za-z,*]*)',
			'import\s*([A-Za-z]*)?(,?)(\s)?%s([A-Za-z,]*)?(,?)(\s)?',
		]

		# I just do some list comprehension here to account for the 
		# repeated information in each regex flare
		self.regex_flares = [ flare % dangerous_modules for flare in self.regex_flares ]


	# Actually perform the scan.
	#	The target file name is in self.target, and an open file object
	#	for that file is in self.file. Evaluate the file however you
	#	wish then output your results to standard output.
	def scan(self):
		self.report_flares()
		return


	# This function is again added for convenience because it is a common
	# task: run through the file to detect and report any regex flares.
	# In your own scanner you can simply set the self.regex_flares list and 
	# call this function to find the occurences of anything you would like.
	def report_flares(self):

		# Start keeping track of the position...
		line_number = 1

		for line in self.file.readlines():
			for flare in self.regex_flares:
				matched = re.search( flare, line )

				if ( matched ):
					match = matched.group().strip()
					notify = c(self.target)+ " (line %d): " + R(match)
					notify = notify % line_number
					log.warn( notify )

			# Account for moving to the next line...
			line_number += 1


	# You may use this static method to match this scan with a specific
	#	file type. This is INSTEAD OF the specifiers in vulnscan.py
	#	(e.g. mimeTypes, extensions, and allexec). If you override this
	#	method those fields become ignored. This evaluation should be
	#	quick and return either true or false.
	# @staticmethod
	# def match(target, mimetype, file, data):
	# 	return False