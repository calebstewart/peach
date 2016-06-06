# -*- coding: utf-8 -*-
# @Author: john
# @Date:   2016-05-27 08:42:28
# @Last Modified by:   John Hammond
# @Last Modified time: 2016-06-06 15:25:01
from regexscanner import RegexScanner
import re


class ModuleScanner(RegexScanner):
	
	# Nothing needs to be done here, but you can initialize any object data
	# you wish to use later on!
	def __init__(self, scannerId, mesgQueue):
		super(ModuleScanner, self).__init__(scannerId, mesgQueue)

		self.name = 'python import scanner'

		# Setup match criteria
		self.extensions = [ '.py' ]

		# I note this in a separate variable because they are used in
		# each regex
		dangerous_modules = '(__os__|os|subprocess|sh|commands|fabric|paramiko|pickle)'
		regex_flares = [
			'from\s*%s\s*import\s*[A-Za-z,*]*',
			'import\s*[A-Za-z]*?,?\s?%s[A-Za-z,]*?,?\s?',
		]

		# Define the patterns RegexScanner will use
		self.patterns = [
			{
				'name': 'importing unsafe module \'{1}\'',
				're': re.compile(flare % dangerous_modules)
			} for flare in regex_flares
		]


class FunctionScanner(RegexScanner):

	def __init__(self, scannerId, mesgQueue):
		super(FunctionScanner, self).__init__(scannerId, mesgQueue)

		self.name = 'python function call scanner'

		self.extensions = [ '.py' ]

		self.patterns = [
			{
				'name': 'call to unsafe function \'{1}\'',
				're': re.compile(r'.*(system)\(.*\).*')
			}
		]

class SQLScanner(RegexScanner):

	def __init__(self, scannerId, mesgQueue):
		super(SQLScanner, self).__init__(scannerId, mesgQueue)

		self.name = 'python sql usage scanner'

		self.extensions = [ '.py' ]

		sql_verbs = '(SELECT|CREATE|UPDATE|DELETE|UNION|INSERT|GRANT|ALTER|DROP|TRUNCATE|START|DESCRIBE|USE|REPLACE|COMMIT|ROLLBACK)'
		regex_flares = [
			'"%s .*"\s*?\+',  						#	"SELECT * FROM " +
			"'%s .*'\s*?\+",  						#	'SELECT * FROM ' +

			'\+\s*?"%s .*"',  						#	+ "SELECT * FROM "
			"\+\s*?'%s .*'",  						#	+ 'SELECT * FROM '

			'[A-Za-z_]*?\s*?\+=\s*?"%s .*?"',  		#	str += "SELECT * FROM "
			"'[A-Za-z_]*?\s*?\+=\s*?'%s .*'",  		#	str += 'SELECT * FROM '

			'"%s .*".__add__\(.*?\)',				#	"SELECT * FROM ".__add__(...)
			"'%s .*'.__add__\(.*?\)",				#	'SELECT * FROM '.__add__(...)
			
			'[A-Za-z_].__add__\(\s*?"%s .*"\s*?\)',	#	str.__add__("SELECT * FROM ")
			"[A-Za-z_].__add__\(\s*?'%s .*'\s*?\)",	#	str.__add__('SELECT * FROM ')

			'".*?".__add__\(\s*?"%s .*"\s*?\)',		#	"".__add__("SELECT * FROM ")
			'\'.*?\'.__add__\(\s*?"%s .*"\s*?\)',	#	''.__add__("SELECT * FROM ")
			"\".*?\".__add__\(\s*?'%s .*'\s*?\)",	#	"".__add__('SELECT * FROM ')
			"'.*?'.__add__\(\s*?'%s .*'\s*?\)",		#	''.__add__('SELECT * FROM ')
		]


		self.patterns = [
			{
				'name': 'possible sql usage & injection \'{0}\'',
				're': re.compile(flare % sql_verbs)
			} for flare in regex_flares
		]