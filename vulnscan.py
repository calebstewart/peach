#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:02:36
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-27 14:50:29
import argparse
import json
import os
from Queue import Queue
from pwn import *
from colors import *
from scan.scanner import Scanner
import stat

class VulnerabilityScanner:

	def __init__(self, follow = False, timeout = None, config='vulnscan.json', output=None):
		self.follow = follow
		self.timeout = timeout
		self.scans = []
		self.output = output
		self.load_config(config)
		self.results = {
			'scanners': [ scan['classname'] for scan in self.scans ],
			'targets': { }
		}

	# Load a scan definition from a configuration file
	def load_scan(self, config):
		# Build a scan object based on the configuration information
		scan = {
			"name": config['name'],
			"extensions": config.get('extensions', []),
			"mimeTypes": config.get('mimeTypes', []),
			"allexec": config.get('allexec', False),
			"classname": config['module'] + '.' + config['class']
		}

		# Load the module and extract the class
		pkg = __import__('scan.' + config['module'])
		module = getattr(pkg, config['module'])
		classobj = getattr(module, config['class'])
		scan['class'] = classobj

		# Add the new scan
		self.scans.append(scan)

	# Load a configuration file
	def load_config(self, filename):
		try:
			with open(filename) as file:
				self.config = json.load(file)
		except Exception as e:
			log.error('unable to load config file.')
			pass

		for scan in self.config['scans']:
			self.load_scan(scan)


	# Traverse the directory tree and run all matching scanners
	# on all matching files within the tree.
	def scan_dir(self, directory):
		for dirname, dirlist, filelist in os.walk(directory, followlinks=self.follow):
			for d in dirlist:
				self.scan(os.path.join(dirname, d))
			for f in filelist:
				self.scan(os.path.join(dirname, f))

	# Run all matching scanners on the given file path
	def scan_file(self, path):
		msgs = Queue()
		active_scans = []
		# Match scanners to the file and start them
		for scan in self.scans:
			if scan['class'].match(scan, path):
				log.info('started scan {0} for target {1}'.format(y(scan['name']), C(os.path.basename(path))))
				active_scans.append(scan['class'](path, len(active_scans), msgs))
				active_scans[-1].start()

		scans_left = len(active_scans)

		# Wait for scanners to finish
		while scans_left != 0:
			msg = msgs.get()
			if msg['event'] == Scanner.FINISHED:
				active_scans[msg['id']].join()
				scans_left = scans_left - 1
			elif msg['event'] == 'HIT':
				self.log(path, active_scans[msg['id']], msg)
				# if msg['level'] == Scanner.WARN:
				# 	log.warn(msg['text'])
				# elif msg['level'] == Scanner.ERROR:
				# 	log.error(msg['text'])
				# else:
				# 	log.info(msg['text'])

		if self.output != None:
			self.dump(self.output)

		log.info('finished scanning %s' % C(os.path.basename(path)))

	def log(self, target, scanner, mesg):
		if self.output == None:
			log.warn('%s (%s): %s' % (c(target), mesg['where'], R(mesg['vuln'])))
		else:
			result = {
				'scanner': scanner.__class__.__name__,
				'vuln': mesg['vuln'],
				'where': mesg.get('where', ''),
			}
			if self.results['targets'].get(target, None) == None:
				self.results['targets'][target] = []
			self.results['targets'][target].append(result)

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
# Not implemented yet
#parser.add_argument('-t', '--timeout', action='store', type=float, default=5, help='timeout for each scan in seconds (default: 5)')
args = parser.parse_args()

scanner = VulnerabilityScanner(follow=args.follow, config=args.config, output=args.output)
for path in args.paths:
	scanner.scan(path)