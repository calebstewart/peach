# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:19:49
# @Last Modified by:   Caleb Stewart
# @Last Modified time: 2016-06-01 11:22:03
import threading
import os
import mimetypes
from pwn import *
import copy

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
	def scan(self, target, progress):
		progress.status('Scanner subclass did not implement the scan method!')
		return

	# This class used to subclass Thread, but... now it doesn't.
	def start(self, target, progress):
		if self.thread != None:
			return
		self.thread = threading.Thread(target=self.run, args=(target,progress))
		self.thread.start()

	# Wait for the scan to finish
	def wait(self, timeout=None):
		if self.thread == None:
			return
		self.thread.join(timeout=timeout)
		del(self.thread)
		self.thread = None

	# Run the scanner, then signal the parent we are done.
	def run(self, target, progress):
		try:
			self.scan(target, progress)
		finally:
			self.queue.put({ 'id': self.ID, 'event': Scanner.FINISHED})

	def hit(self, vuln, where, info = {}):
		info.update({ 'id': self.ID, 'event': Scanner.HIT, 'vuln': vuln, 'where': where})
		self.queue.put(copy.deepcopy(info))

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