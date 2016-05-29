# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-29 14:23:44
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-29 17:26:19
from scanner import Scanner
import re

# Generic regular expression scanner.
# Scans each file for all patterns stored in the self.patter
# array. Each pattern is a dictionary with the 'name' and 
# 're' keys. 'name' is passed to self.hit, while 're' is a
# compiled regular expression.
#
# the pattern name is formatted with the match groups from
# the pattern. Match group 0 is the entire matched string,
# while match group N is the Nth group (if any).
class RegexScanner(Scanner):
	
	def __init__(self, scannerId, mesgQueue):
		super(RegexScanner, self).__init__(scannerId, mesgQueue)
		self.name = 'regex scanner'

	def scan(self, target):
		with open(target) as file:
			for lineno, line in enumerate(file):
				for p in self.patterns:
					match = p['re'].search(line)
					if match:
						if len(match.groupdict()) > 0:
							groups = list(match.group(range(0, len(match.groupdict())+1)))
						else:
							groups = [match.group(0)]
						groups = [ group.strip() for group in groups ]
						self.hit(p['name'].format(*groups), 'line {0}'.format(lineno))

# Example implementation of the RegexScanner
# This scanner will match files with text/plain mime type
# and looks for text matching the pattern 'example' while
# ignoring case.
class RegexScannerExample(RegexScanner):

	def __init__(self, scannerId, mesgQueue):
		super(RegexScannerExample, self).__init__(scannerId, mesgQueue)
		self.name = 'regex example scanner'
		self.mimeTypes = [ 'text/plain' ]
		self.patters = [
			{
				'name': 'example pattern',
				're': re.compile('example', re.IGNORECASE)
			}
		]