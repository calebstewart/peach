#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:02:36
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-27 03:10:24
import argparse
import json
import mimetypes
import os
from Queue import Queue
from pwn import *

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('directory', help='base directory to evaluate')
parser.add_argument('-nf', '--nofollow', action='store_false', dest='follow', help='don\'t follow symlinks')
parser.add_argument('-f', '--follow', action='store_true', dest='follow', default=True, help='follow simlinks (default)')
# Not implemented yet
#parser.add_argument('-t', '--timeout', action='store', type=float, default=5, help='timeout for each scan in seconds (default: 5)')
args = parser.parse_args()

# Open the configuration
with open('vulnscan.json') as file:
	config = json.load(file)

# import the base scan module
scan = __import__('scan')

# Load all scan classes
for name in config['scans']:
	# For submodules, __import__ still returns the base module (scan in this case)
	__import__('scan.'+config['scans'][name]['module'])
	# So, we need to find the newly loaded module within the scan module after loading
	module = getattr(scan, config['scans'][name]['module'])
	# NOW, we can find the class name within that module... D:
	config['scans'][name]['classobj'] = getattr(module, config['scans'][name]['class'])

# Perform all relevant scans on a given target
def scan_target(target):
	queue = Queue() # Queue for notifyin when scans are finished

	# Collect some information about the target that all
	# scans likely need
	mimetype = mimetypes.guess_type(target, strict=False)
	_, ext = os.path.splitext(target)
	is_exec = os.access(target, os.X_OK)
	# Open the target file
	file = open(target)
	# How many scans were started?
	scan_count = 0

	# Iterate through all scans and check for matches
	# If a match is found, start the scan
	for name in config['scans']:
		scan = config['scans'][name]
		if scan['classobj'].match(target, mimetype, file, scan):
			scan['classobj'](target, file, queue).start()
			scan_count = scan_count + 1
	log.info('started {0} scans for target {1}'.format(scan_count, os.path.basename(target)))
	# Wait for scans to finish
	while scan_count > 0:
		try:
			queue.get() # Will block until a scan finishes
			scan_count = scan_count - 1 # decrease the number of scans we are waiting on decrease 
		except Exception, e:
			raise e

# Walk the directories and iterate over every file
for dirname, dirlist, filelist in os.walk(args.directory, followlinks=args.follow):
	for target in filelist:
		scan_target(os.path.join(dirname, target))