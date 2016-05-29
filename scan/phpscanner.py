# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 02:59:41
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-29 16:56:11
import regexscanner
import re

class PHPScanner(regexscanner.RegexScanner):

	
	# Nothing needs to be done here, but you can initialize any object data
	# you wish to use later on!
	def __init__(self, scannerId, mesgQueue):
		super(PHPScanner, self).__init__(scannerId, mesgQueue)

		self.name = 'PHP function call scanner'

		# Setup scanner match criteria
		self.extensions = [ '.php', '.php3', '.php4', '.php5', '.phtml' ]

		# Setup the patterns RegexScanner will search for inside of targets.
		self.patterns = [
			{
				'name': 'system() call',				# Name is passed to self.hit
				're': re.compile(r"""system\(.*\)""")	# Used to match a line
			}
		]