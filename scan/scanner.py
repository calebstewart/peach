# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:19:49
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-27 02:47:56
import threading
import os
from pwn import *

# Generic scanner class
class Scanner(threading.Thread):

	target = None
	queue = None
	file = None

	# `target` is the full path to the target executable.
	# `queue` is a message queue to signal when the scanner is finished.
	def __init__(self, target, file, queue):
		super(Scanner, self).__init__()
		self.target = target
		self.queue = queue
		self.file = file
		return

	# The subclass should redefine this!
	def scan(self):
		log.warn('Scanner subclass did not implement the scan method!')
		return

	# Run the scanner, then signal the parent we are done.
	def run(self):
		try:
			self.scan()
		finally:
			self.queue.put('COMPLETE')

	# Static method to check if the scan matches the target
	# 	You may override this in subclasses, but that will
	#	disable the search terms in vulnscan.json!
	@staticmethod
	def match(target, mimetype, file, scan):
		if mimetype in scan.get('mimeTypes', []):
			return True
		if os.path.splitext(target)[1] in scan.get('extensions', []):
			return True
		if os.access(target, os.X_OK) == True and scan.get('allexec', False) == True:
			return True