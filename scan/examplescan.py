# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 02:59:41
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-27 03:15:18
import scanner

# This is a very simply example scanner!
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
	
	# Nothing needs to be done here!
	def __init__(self, target, file, queue):
		super(ExampleScanner, self).__init__(target, file, queue)

	# Actually perform the scan.
	#	The target file name is in self.target, and an open file object
	#	for that file is in self.file. Evaluate the file however you
	#	wish then output your results to standard output.
	def scan(self):
		return

	# You may use this static method to match this scan with a specific
	#	file type. This is INSTEAD OF the specifiers in vulnscan.py
	#	(e.g. mimeTypes, extensions, and allexec). If you override this
	#	method those fields become ignored. This evaluation should be
	#	quick and return either true or false.
	# @staticmethod
	# def match(target, mimetype, file, data):
	# 	return False