# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 02:59:41
# @Last Modified by:   John Hammond
# @Last Modified time: 2016-05-27 10:05:27
import scanner
import re
from pwn import *
from colors import *
# This package has color automatically, inherited from the top-level module


class ScanCatchAll(scanner.Scanner):

	
	# Nothing needs to be done here, but you can initialize any object data
	# you wish to use later on!
	def __init__(self, target, file, queue):
		super(ScanCatchAll, self).__init__(target, file, queue)



		# In this list you can add any Regex patterns you want to report
		# on. This is added for convenience since many scanners may just be
		# hunting for occurences of dangerous or vulnerable code. 
		self.regex_flares = [
			
			# By default this is intialized to be empty; you should populate
			# it in your own scanner!
		]


	# Actually perform the scan.
	#	The target file name is in self.target, and an open file object
	#	for that file is in self.file. Evaluate the file however you
	#	wish then output your results to standard output.
	def scan(self):
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


	# This scanner is purposely meant to handle all files; with that in 
	# consideration it will always match any target.
	@staticmethod
	def match(target, mimetype, file, data):
		return True

