# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:19:49
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-27 01:30:57
import threading
from pwn import *

# Generic scanner class
class Scanner(threading.Thread):

	target = None
	queue = None

	# `target` is the full path to the target executable.
	# `queue` is a message queue to signal when the scanner is finished.
	def __init__(self, target, queue):
		super(Scanner, self).__init__()
		self.target = target
		self.queue = queue
		return

	# The subclass should redefine this!
	def scan(self):
		log.warn('Scanner subclass did not implement the scan method!')
		return

	# Run the scanner, then signal the parent we are done.
	def run(self):
		self.scan()
		self.queue.put('COMPLETE')