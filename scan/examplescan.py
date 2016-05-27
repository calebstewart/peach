# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 02:59:41
# @Last Modified by:   John Hammond
# @Last Modified time: 2016-05-27 08:55:05
import scanner
import re
from colorama import *

# This is a very simple example scanner!
# 	The example entry in vulnscan.json has no match criteria, therefore
#	the example scanner will never match any target, but here are some
#	options for matching:
#
#	In vulnscan.json:
#		"mimeTypes": An array of mime type strings which match this scan.
#		"extensions": An array of file extensions which match this scan.
#						The extension INCLUDES the period! e.g. a C++ source
#						file extension is ".cpp".
#		"allexec": This means that the scan matches all executable files.
#	Within this source file:
#		You may override all vulnscan.json criteria by overriding the
#		static "match" method below. You may implement whatever logic
#		you desire to match a target file with your scan using this
#		method.
class ExampleScanner(scanner.Scanner):

	
	# Nothing needs to be done here, but you can initialize any object data
	# you wish to use later on!
	def __init__(self, target, file, queue):
		super(ExampleScanner, self).__init__(target, file, queue)



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
	def check_flares(self):

		# Start keeping track of the position...
		line_number = 1

		for line in self.file.readlines():
			for flare in self.regex_flares:
				matched = re.search( flare, line )

				if ( matched ):
					match = matched.group()
					notify = Fore.CYAN + self.target + Fore.RESET + " (line %d): " + Fore.RED + Style.BRIGHT + "%s" +  Fore.RESET + Style.NORMAL
					notify = notify % ( line_number, match )
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