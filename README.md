Vulnerability Scanning Framework
============

This tool aims to look through files in a given directory to detect any unsafe, vulnerable, or dangerous function calls. It is designed to be extensible and easy to understand; you can "plug-and-play" modules that specify criteria on which types of files will trigger what 'scans,' in which you determine what action it should take to find and report dangerous content within each file.

Usage
--------

```
$ ./vulnscan.py -h
usage: vulnscan.py [-h] [-nf] [-f] directory

positional arguments:
  directory        base directory to evaluate

optional arguments:
  -h, --help       show this help message and exit
  -nf, --nofollow  don't follow symlinks
  -f, --follow     follow simlinks (default)
```

