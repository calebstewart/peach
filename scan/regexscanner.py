# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-29 14:23:44
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-29 15:43:35
from scanner import Scanner
import re

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
						match = match.group().strip()
						self.hit(p['name'], 'line {0}'.format(lineno))