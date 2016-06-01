Peach Fuzz - Scanner
====================

This directory houses all of the basic "Scanners" which look for a variety of common vulnerability in both source, script, and binary files. The base class for all scanners is `scan.scanner.Scanner`. This class provides a common interface for matching target files to scanners when traversing a directory tree. In order to create a custom scanner, you must override the constructor, and the `scan` method. You must also either specify match criteria using the default matching members or override the `match` function in order for your scanner to match a target and be used.

An example can be seen in the [example scanner][1]. This scanner always hits at "line 0", although never actually opens the target file. It also matches every file due to a overridden match function.

There should be __NO__ [fuzzers][2] implemented here! All scanner should be passive and only examine the files. No scanners should modify or execute the targets! That is what fuzzers are for!

Scanner Base Class
------------------

__`def __init__(self, scannerId, mesgQueue)`__

You must pass the parameters up to the Scanner base class constructor before any other setup code. Here, you may setup things like your scanner name, and default match criteria (see Members below).

__`def scan(self, target)`__
	
Expected to be overridden by subclasses. Called after matching a target to the scanner. Returns nothing, but calls the `hit` method for each scan hit.

__`def match(self, target)`__

Attempts to match the given target to the scanner. If the target matches, return True. By default, this method evaluates the `mimeTypes`,`extensions`, and `allexec` members to match the target, but may be overridden to provide custom matching.

__`def hit(description, location, info={})`__

Called during the scan function by the subclass. Reports a scan hit back to the main scanning thread which will either log it to the console or to the output file. If `info` is provided, its contents will be dumped to the output file along with the description and location. If no output file is given (e.g. output is going to the command line), then info is ignored.

__`self.name`__
	
The name of the scanner. Given in the context `"started {0} on file {1}".format(self.name, target)`. For example, "python import scanner".

__`self.mimeTypes`__

Array of matching MIME Types. The targets [MIME type] is guessed using the python module `mimetypes` like so: `mimetypes.guess_type(target, strict=False)`.

__`self.extensions`__

The list of file extensions that match the target to the scanner. These extensions include the dot (e.g. the extension for C++ source file is ".cpp").

__`self.allexec`__

A true or false value specifying whether or not to match every executable file.

[JSON]: https://en.wikipedia.org/wiki/JSON
[MIME type]: https://en.wikipedia.org/wiki/Media_type
[Python]: http://python.org/
[thread]: https://en.wikipedia.org/wiki/Thread_%28computing%29
[threads]: https://en.wikipedia.org/wiki/Thread_%28computing%29
[command-line arguments]: https://www.cs.bu.edu/teaching/c/program-args/
[program arguments]: https://www.cs.bu.edu/teaching/c/program-args/
[ELF]: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
[shell]: https://en.wikipedia.org/wiki/Bash_%28Unix_shell%29
[SQL]: https://en.wikipedia.org/wiki/SQL
[1]: ./examplescanner.py
[2]: ../fuzz/README.md
