Peach Fuzz - Fuzzer
===================

This directory houses all of the "Scanners" which also perform automated fuzzing on all executables. The base class for all fuzzers is `fuzz.fuzzer.Fuzzer`. This class sets up the match criteria and defines the scan function for given targets (see [Scanner Documentation][1]). For a Fuzzer subclass, you need only define one method and the constructor to begin fuzzing.

The needed method is called `fuzz` and takes one parameter, the target executable path. The method is actually a generator which yields a tuple with the following elements (in order):

* Arguments array
* Environment array
* String specifying standard input
* Boolean value defining what to do when a crash is found

The arguments array is required, but may be an empty array (the target name will be prepended before executing). The environment array is optional, but if unchanged must be `None`. Standard input should be either the output to be sent to the process or an empty string. Lastly, a boolean value must be specified. If it is true, a segmentation fault causes this fuzzer to complete and all other trials be aborted. If false, then a segmentation fault does not interrupt the fuzzer (all trials will complete no matter what).

An [example Fuzzer][2] is included and shows the most basic fuzzer. It only yields one fuzzer trial with no arguments, environment changes, or standard input, but it is a place to start.

[1]: ../scan/README.md
[2]: ./example.py