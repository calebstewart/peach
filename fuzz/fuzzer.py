# -*- coding: utf-8 -*-
# @Author: Caleb Stewart
# @Date:   2016-05-31 16:04:38
# @Last Modified by:   Caleb Stewart
# @Last Modified time: 2016-05-31 16:29:26
from scan.scanner import Scanner
from pwn import *
import time
import os
import signal

class Fuzzer(Scanner):
	
	def __init__(self, target, ID, queue):
		super(Fuzzer, self).__init__(ID, queue) 
		self.name = "generic fuzzer"
		self.allexec = True
		self.trialTimeout = 5 # Maximum of 5 second timeout per fuzzer trial

	def scan(self, target):
		for args,env in self.fuzz(target):
			end_time = time.ctime() + self.trialTimeout
			p = process([target] + args, env=env)
			self.communicate(p)
			# This is a nasty busy loop... :(
			while time.ctime() < end_time:
				time.sleep(0.01)
			if p.poll() == None:
				p.kill()
			else:
				code = p.poll()
				if os.WIFSIGNALED(code) and os.WTERMSIG(code) == signal.SIGSEGV:
					self.hit('found segmentation fault!', str(args) + '\n' + str(env))
