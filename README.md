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
  -f, --follow     follow symlinks (default)
```

File & Directory Information
------

* [`scan`](scan/)
	
	This directory hosts all the classes that can be duplicated and extended for specific file "scans," in which you could do pretty much anything you want. They are just housed in this folder to keep things clean.

* [`test`](test/)

	This directory holds anything that has been often used to test some of the scanners. You can add to it as you please.

* [`vulnscan.json`](vulnscan.json)

	This acts like the global configuation; in this [JSON] file you specify what scans you want to run for all of the files processed, and determine whatever criteria you want to use to identify those files (file extension, [MIME type], or executable).

* [`vulnscan.py`](vulnscan.py)

	This is the core of the utility; the [Python] script that kickstarts all [threads] and scans from the given [command-line arguments]. 

That's it! The idea behind the tool is simple; the real power comes from building scanners to detect and report any mischievous content or code in large amounts of unknown data. So add your own scanner!
 
[JSON]: https://en.wikipedia.org/wiki/JSON
[MIME type]: https://en.wikipedia.org/wiki/Media_type
[Python]: http://python.org/
[thread]: https://en.wikipedia.org/wiki/Thread_%28computing%29
[threads]: https://en.wikipedia.org/wiki/Thread_%28computing%29
[command-line arguments]: https://www.cs.bu.edu/teaching/c/program-args/
[program arguments]: https://www.cs.bu.edu/teaching/c/program-args/
[ELF]: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format