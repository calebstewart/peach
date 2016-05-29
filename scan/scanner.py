# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:19:49
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-29 15:45:06
import threading
import os
import mimetypes
from pwn import *

# Generic scanner class
class Scanner(object):

	WARN = 'WARN'
	ERROR = 'ERROR'
	FINISHED = 'FINISHED'
	HIT = 'HIT'

	# `scannerId` is a unique identifier for this scanner
	# `mesgQueue` is a message queue to signal when the scanner is finished.
	def __init__(self, scannerId, mesgQueue):
		super(Scanner, self).__init__()
		self.queue = mesgQueue
		self.ID = scannerId
		self.allexec = False
		self.mimeTypes = []
		self.extensions = []
		self.name = 'Default Scanner Name'
		self.thread = None
		return

	# The subclass should redefine this!
	def scan(self, target):
		log.error('Scanner subclass did not implement the scan method!')
		return

	# This class used to subclass Thread, but... now it doesn't.
	def start(self, target):
		if self.thread != None:
			return
		self.thread = threading.Thread(target=self.run, args=(target,))
		self.thread.start()

	# Wait for the scan to finish
	def wait(self, timeout=None):
		if self.thread == None:
			return
		self.thread.join(timeout=timeout)
		self.thread = None

	# Run the scanner, then signal the parent we are done.
	def run(self, target):
		try:
			self.scan(target)
		finally:
			self.queue.put({ 'id': self.ID, 'event': Scanner.FINISHED})

	def hit(self, vuln, where):
		self.queue.put({ 'id': self.ID, 'event': Scanner.HIT, 'vuln': vuln, 'where': where})

	# Method to check if the scan matches the target
	# 	You may override this in subclasses, but that will
	#	disable the mimeTypes, extensions, and allexec
	#	search criteria.
	def match(self, target):
		mimetype = mimetypes.guess_type(target, strict=False)
		_,extension = os.path.splitext(target)
		isexec = os.access(target, os.X_OK)
		if mimetype in self.mimeTypes:
			return True
		if extension in self.extensions:
			return True
		if isexec and self.allexec:
			return True