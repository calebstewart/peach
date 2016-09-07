Peach Fuzz - Vulnerability Scanning Framework
============

This tool aims to look through files in a given directory to detect any unsafe, vulnerable, or dangerous function calls. It is designed to be extensible and easy to understand; you can "plug-and-play" modules that specify criteria on which types of files will trigger what 'scans,' in which you determine what action it should take to find and report dangerous content within each file.

Also, it may be run as an experimental automated fuzzing tool. Given effective modules, the framework can be adapted to automatically fuzz executables. You may implement fuzzers using the generic `fuzz.fuzzer.Fuzzer` class. WARNING: this is a subclass of `scan.scanner.Scanner`, but will EXECUTE all files with executable permission! Be careful!

Usage
--------

```
$ ./peach.py -h
usage: peach.py [-h] [-s] [-f] [--follow] [-c CONFIG] [-o OUTPUT] [-sh] [-nh]
                paths [paths ...]

positional arguments:
  paths                 files and directories to scan

optional arguments:
  -h, --help            show this help message and exit
  -s, --scan            use configuration file for vulnerability scanning
                        (vulnscan.json).
  -f, --fuzz            use configuration file for automated fuzzing
                        (fuzzing.json).
  --follow              follow symbolic links when scanning directories
  -c CONFIG, --config CONFIG
                        specify a custom configuration file (default:
                        vulnscan.json)
  -o OUTPUT, --output OUTPUT
                        output results to the specified JSON file
  -sh, --scan-hidden    Scan hidden files and directories (default)
  -nh, --no-hidden      Do not scan hidden files and directories
```

File & Directory Information
------

* [`peach.py`](peach.py)

	This is the core of the utility; the [Python] script that kickstarts all [threads] and scans from the given [command-line arguments]. 

* [`scan`](scan/)
	
	This directory hosts all the classes that can be duplicated and extended for specific file "scans," in which you could do pretty much anything you want. They are just housed in this folder to keep things clean.

* [`vulnscan.json`](vulnscan.json)

	This acts like the global configuation; in this [JSON] file you specify what scans you want to run for all of the files processed, and determine whatever criteria you want to use to identify those files (file extension, [MIME type], or executable). All scanners listed in this configuration should be merely that: scanners. No fuzzers should be listed here!

* [`fuzzing.json`](fuzzing.json)

	This file is similar to `vulnscan.json` except that it contains references to fuzzers and can be used to start automatically fuzzing a directory or file. WARNING: using this config will execute ALL files with executable permissions! Be careful using it!

* [`test`](test/)

	This directory holds anything that has been often used to test some of the scanners. You can add to it as you please.

* [`colors.py`](colors.py)

	This small module acts as a wrapper for [`colorama`][colorama], in an effort to supply some shorthand function calls.

That's it! The idea behind the tool is simple; the real power comes from building scanners to detect and report any mischievous content or code in large amounts of unknown data. So add your own scanner!

Note
----

You may need to increase the maximum number of open files on your system in order to use all the fuzzers provided with this tool. Due to the fuzzers being run simultaneously, a large number of open files quickly accrues. On most modern systems, the limit is placed at 1024, which will cause a "Out of files" (EMFILE) error. Increasing the max open file count for your system should solve the problem.
 
[JSON]: https://en.wikipedia.org/wiki/JSON
[MIME type]: https://en.wikipedia.org/wiki/Media_type
[Python]: http://python.org/
[thread]: https://en.wikipedia.org/wiki/Thread_%28computing%29
[threads]: https://en.wikipedia.org/wiki/Thread_%28computing%29
[command-line arguments]: https://www.cs.bu.edu/teaching/c/program-args/
[program arguments]: https://www.cs.bu.edu/teaching/c/program-args/
[ELF]: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
[colorama]: https://pypi.python.org/pypi/colorama
[constructor]: https://en.wikipedia.org/wiki/Constructor_%28object-oriented_programming%29