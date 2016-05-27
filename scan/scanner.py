# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:19:49
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-27 12:52:58
import threading
import os
import mimetypes
from pwn import *

# Generic scanner class
class Scanner(threading.Thread):

	WARN = 'WARN'
	ERROR = 'ERROR'
	FINISHED = 'FINISHED'

	# `target` is the full path to the target executable.
	# `queue` is a message queue to signal when the scanner is finished.
	def __init__(self, target, ident, queue):
		super(Scanner, self).__init__()
		self.target = target
		self.queue = queue
		self.ID = ident
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
			self.queue.put({ 'id': self.ID, 'event': Scanner.FINISHED})

	def hit(self, level, mesg):
		self.queue.put({ 'id': self.ID, 'event': 'HIT', 'level': level, 'text': mesg })

	# Static method to check if the scan matches the target
	# 	You may override this in subclasses, but that will
	#	disable the search terms in vulnscan.json!
	@staticmethod
	def match(scan, target):
		mimetype = mimetypes.guess_type(target, strict=False)
		_,extension = os.path.splitext(target)
		isexec = os.access(target, os.X_OK)
		if mimetype in scan['mimeTypes']:
			return True
		if extension in scan['extensions']:
			return True
		if isexec and scan['allexec']:
			return True