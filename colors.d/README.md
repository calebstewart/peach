Vulnerability Scanning Framework :: `colors`
============

This small package (I don't know if I would even call it that) acts as a wrapper for [`colorama`][colorama], in an effort to supply some shorthand function calls.

It simply creates one-character functions that return the same string passed to it, just wrapped in the [`colorama`][colorama] code. It is all done in the [`__init__.py`](__init__.py) [constructor] so all you need for import anywhere in the utility is simply

```
from colors import *
```
 
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