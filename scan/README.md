Vulnerability Scanning Framework :: `scan`
============

This directory holds anything that has been often used to test some of the scanners. You can add to it as you please.

__The most important file here is the [`scanner.py`](scanner.py), as it is the base class that all scanners will inherit from.__ [`examplescan.py`](examplescan.py) offers a good indicator of what a scannner can typically look like, and it offers a few convenience functions that you can of course choose to utilize or disregard.

All other `.py` files in this folder are specific scanners that have been tailored to one specific usage. Common things to detect:

* Executing [Shell] commands ( i.e. `os.system('/bin/bash')` )
* Sensitive Files ( i.e. `/etc/shadow` )
* Unsanitized SQL statements ( i.e. `"SELECT " + column + "FROM books_db"` )
* Dangerous [ELF] Symbols ( i.e. `gets`, `strcat` )

... and more! 

 
[JSON]: https://en.wikipedia.org/wiki/JSON
[MIME type]: https://en.wikipedia.org/wiki/Media_type
[Python]: http://python.org/
[thread]: https://en.wikipedia.org/wiki/Thread_%28computing%29
[threads]: https://en.wikipedia.org/wiki/Thread_%28computing%29
[command-line arguments]: https://www.cs.bu.edu/teaching/c/program-args/
[program arguments]: https://www.cs.bu.edu/teaching/c/program-args/
[ELF]: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format