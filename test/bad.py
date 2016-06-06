# -*- coding: utf-8 -*-
# @Author: caleb
# @Date:   2016-05-27 12:51:08
# @Last Modified by:   John Hammond
# @Last Modified time: 2016-06-06 14:31:17
import os
from subprocess import *

# This could be bad...
os.system('sh') 

# And maybe we could be a vulnerable web app...
some_variable = "that you could control"
database_query = "SELECT * FROM " + some_variable