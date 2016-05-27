#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 00:02:36
# @Last Modified by:   caleb
# @Last Modified time: 2016-05-27 01:42:15
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

# Load all scan classes
for name in config['scans']:
	config['scans'][name]['classobj'] = getattr(__import__(config['scans'][name]['module']), config['scans'][name]['class'])

# Perform all relevant scans on a given target
def scan_target(target):
	queue = Queue()
	mimetype = mimetypes.guess_type(target, strict=False)
	_, ext = os.path.splitext(target)
	is_exec = os.access(target, os.X_OK)
	scan_count = 0
	for name in config['scans']:
		scan = config['scans'][name]
		if mimetype in scan.get('mimeTypes', []) or \
				ext in scan.get('extensions', []) or \
				(is_exec and scan.get('allexec', False) == True):
			log.info('scanning {1} for {0}'.format(name, os.path.basename(target)))
			scan['classobj'](target, queue).start()
			scan_count = scan_count + 1
	log.info('started {0} scans for target {1}'.format(scan_count, os.path.basename(target)))
	# Wait for scans to finish
	while scan_count > 0:
		try:
			queue.get()
			scan_count = scan_count - 1
		except Exception, e:
			raise e

for dirname, dirlist, filelist in os.walk(args.directory, followlinks=args.follow):
	for target in filelist:
		scan_target(os.path.join(dirname, target))