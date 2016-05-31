#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:02:36
# @Last Modified by:   Caleb Stewart
# @Last Modified time: 2016-05-31 16:46:43
import argparse
import json
import os
from Queue import Queue
from pwn import *
from colors import *
from scan.scanner import Scanner
import stat

class VulnerabilityScanner:

	def __init__(self, scanHidden = True, follow = False, timeout = None, config='vulnscan.json', output=None):
		self.follow = follow
		self.timeout = timeout
		self.scans = []
		self.output = output
		self.queue = Queue()
		self.scanHidden = scanHidden
		self.load_config(config)
		self.results = {
			'scanners': [ scan.__module__ + '.' + scan.__class__.__name__ for scan in self.scans ],
			'targets': { }
		}

	# Load a scan definition from a configuration file
	def load_scan(self, classname):
		# Load the module and extract the class
		modulename = '.'.join(classname.split('.')[:-1])
		pkg = __import__(modulename)
		classobj = pkg # This will be the "scan" module first
		for name in classname.split('.')[1:]:
			classobj = getattr(classobj, name)
		scanner = classobj(len(self.scans), self.queue)

		# Add the new scan
		self.scans.append(scanner)

	# Load a configuration file
	def load_config(self, filename):
		try:
			with open(filename) as file:
				self.config = json.load(file)
		except Exception as e:
			raise e
			#log.error('unable to load config file.')
			#pass

		for scan in self.config['scanners']:
			self.load_scan(scan)


	# Traverse the directory tree and run all matching scanners
	# on all matching files within the tree.
	def scan_dir(self, directory):
		for dirname, dirlist, filelist in os.walk(directory, followlinks=self.follow):
			if not self.scanHidden:
				filelist = [f for f in filelist if not f.startswith('.')]
				dirlist[:] = [d for d in dirlist if not d.startswith('.')]
			for f in filelist:
				self.scan(os.path.join(dirname, f))

	# Run all matching scanners on the given file path
	def scan_file(self, path):
		active_scans = 0
		# Match scanners to the file and start them
		for scan in self.scans:
			if scan.match(path):
				log.info('started {0} for target {1}'.format(y(scan.name), C(os.path.basename(path))))
				active_scans = active_scans + 1
				scan.start(path)

		# Wait for scanners to finish
		while active_scans != 0:
			msg = self.queue.get()
			if msg['event'] == Scanner.FINISHED:
				self.scans[msg['id']].wait()
				active_scans = active_scans - 1
			elif msg['event'] == 'HIT':
				self.log(path, self.scans[msg['id']], msg)

		if self.output != None:
			self.dump(self.output)

		log.info('finished scanning %s' % C(os.path.basename(path)))

	def log(self, target, scanner, mesg):
		if self.output == None:
			log.warn('%s (%s): %s' % (c(target), mesg['where'], R(mesg['vuln'])))
		else:
			result = {
				'scanner': scanner.__module__ + '.' + scanner.__class__.__name__,
				'vuln': mesg['vuln'],
				'where': mesg.get('where', ''),
			}
			if self.results['targets'].get(os.path.abspath(target), None) == None:
				self.results['targets'][os.path.abspath(target)] = []
			self.results['targets'][os.path.abspath(target)].append(result)

	def dump(self, filename):
		with open(filename, 'w') as file:
			json.dump(self.results, file, indent=4)

	# Scan a directory or a filename
	def scan(self, filepath):
		mode = os.stat(filepath)[stat.ST_MODE]
		if stat.S_ISDIR(mode):
			self.scan_dir(filepath)
		else:
			self.scan_file(filepath)



# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('paths', nargs='+', help='files and directories to scan')
parser.add_argument('-nf', '--nofollow', action='store_false', dest='follow', help='don\'t follow symlinks (default)')
parser.add_argument('-f', '--follow', action='store_true', dest='follow', default=False, help='follow symlinks')
parser.add_argument('-c', '--config', action='store', default='vulnscan.json', help='specify a custom configuration file (default: vulnscan.json)')
parser.add_argument('-o', '--output', action='store', default=None, help='output results to the specified JSON file')
parser.add_argument('-sh', '--scan-hidden', action='store_true', default=True, dest='scanHidden', help='Scan hidden files and directories (default)')
parser.add_argument('-nh', '--no-hidden', action='store_false', dest='scanHidden', help='Do not scan hidden files and directories')
# Not implemented yet
#parser.add_argument('-t', '--timeout', action='store', type=float, default=5, help='timeout for each scan in seconds (default: 5)')
args = parser.parse_args()

scanner = VulnerabilityScanner(scanHidden=args.scanHidden, follow=args.follow, config=args.config, output=args.output)
for path in args.paths:
	scanner.scan(path)