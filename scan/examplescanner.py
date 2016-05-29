# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 02:59:41
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-29 15:42:46
from scanner import Scanner

# This is a very simple example scanner!
#	To enable this scanner, add it to your scanner list inside of the
#	vulnscan config file.
#
#	Currently, the example scanner matches no targets. To add matching
#	rules, you can either setup a few preconfigured matching criteria
#	or define your own.
#
#	To setup predefined criteria, you can set one or more of the
#	class members:
#		* mimeTypes - An array of mimeType strings to match
#		* extensions - An array of extensions (including the dot! e.g. ".cpp")
#		* allexec - Boolean, whether to match all executable files.
#	To create a custom matching criteria, you must override the match
#	function. An example of which may be seen below.
class ExampleScanner(Scanner):

	
	# Nothing needs to be done here, but you can initialize any object data
	# you wish to use later on!
	def __init__(self, scannerId, mesgQueue):
		super(ExampleScanner, self).__init__(scannerId, mesgQueue)

		# Scanner human readable name
		self.name = 'example scanner'

		# These are only valid if you remove the match function from below!
		# mimeTypes example
		# self.mimeTypes = [ 'text/plain' ]
		# extensions example
		# self.extensions = [ '.cpp', '.h', '.c', '.cxx', 'cs' ]
		# all executables example
		# self.allexec = False

	# This function will be called for every matching target
	def scan(self, target):
		# To log a matching vulnerability, call the "hit" member.
		# The first parameter is a short description of the hit,
		# and the second is where it was found. Think of it in
		# context "filename (location): hit description" messages.
		self.hit("Example Hit", "line 0")
		return

	# This method may be used to perform custom or more intricit
	# examinations of a file to make sure it is the correct type,
	# such as checking magic numbers and such.
	#
	# For example purposes, this matches all targets
	def match(self, target):
	 	return True