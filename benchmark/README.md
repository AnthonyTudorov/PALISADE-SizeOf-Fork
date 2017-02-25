PALISADE Library Benchmarks
===========================

The code in this directory provides benchmark measurements of various operations in the PALISADE library.

These benchmarks are useful for determining costs of various operations, and can be used to determine the
improvements made by various changes to the system.

There are several separate benchmark programs which are meant to generate statistics for different layers
in the library. The benchmarks use the Google Benchmark framework; you can run any of the benchmark programs
with the --help option to see what flags are available.

Note that some of the benchmarks should be run with the --benchmark_repetitions flag set to a value of, say,
10, to cause multiple passes to be run for each test. Without this, the more time consuming tests will only
run one time.

Benchmarks are not built by default. Simply run "make benchmark" to build them. The executables for the
benchmarks are located in benchmark/bin

There are two important source files in the benchmark/src folder that control the scope of the benchmarks.

benchmark/stc/ElementParmsHelper.h defines the set of ILElement parameters that are used in the benchmarks
for the lower layers. This file is actually the output of running benchmark/BBprimes.

benchmark/src/EncryptHelper.h determines which of the predefined parameter sets (as established in the library
file src/pke/lib/cryptocontextparametersets-impl.cpp) will be benchmarked.

The benchmark programs are

* BBIMath
* BBVMath
* Encoding
* Lattice
* Crypto
* SHE
