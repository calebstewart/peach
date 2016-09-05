# -*- coding: utf-8 -*-
# @Author: Caleb Stewart
# @Date:   2016-05-31 16:04:38
# @Last Modified by:   Caleb Stewart
# @Last Modified time: 2016-06-01 00:37:39
from scan.scanner import Scanner
from pwn import *
import time
import os
import signal

class Fuzzer(Scanner):
	
	def __init__(self, ID, queue):
		super(Fuzzer, self).__init__(ID, queue) 
		self.name = "generic fuzzer"
		self.allexec = True
		self.trialTimeout = 5 # Maximum of 5 second timeout per fuzzer trial
		self.count = '?'

	def scan(self, target, progress):
		context.log_level = 'WARNING'
		iternum = 0
		for args,env,stdin,done_on_segfault in self.fuzz(target):
			progress.status('executing iteration {0}/{1}'.format(iternum, self.count))
			iternum = iternum + 1
			end_time = time.clock() + self.trialTimeout
			proc = process([target] + args, env=env)
			if proc.connected():
				try:
					proc.send(stdin)
				except EOFError as e:
					pass
			p = log.progress('waiting for process', level='DEBUG')
			# This is a nasty busy loop... :(
			while time.clock() < end_time and proc.poll() == None:
				p.status('still waiting...')
				continue
			if proc.poll() == None:
				p.failure('process timeout')
				proc.kill()
			else:
				p.success('process finished')
				pid = proc.proc.pid
				pattern = (r"""^\[[0-9.]*\] {0}\[{1}\]: segfault at .*$""").format(os.path.basename(target), pid)
				dmesg_output = subprocess.check_output('dmesg | tail', shell=True)
				match = re.search(pattern, dmesg_output, flags=re.M)
				if match != None:
					line = match.group()
					location = int(line.split(' ')[6], 16)
					self.hit('segmentation fault', hex(location), info={'args':args, 'env':env, 'stdin':stdin, 'dmesg': line})
					if done_on_segfault:
						break