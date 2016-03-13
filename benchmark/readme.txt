This is the root directory of the google benchmark library. 
in the google delivery it is called benchmark-master.

We have removed the CMAKE code and replaced it with a makefile called
Makefile.benchmark in the root of the Pallisade tree.
This has only been tested on Ubuntu linux.
It has not been tested on Windows.


This directory tree is not the same format as the deliver from google
note the benchmark-master/src directory has been moved to the
benchmark/include/libsrc directory, and the benchmark-master/test
directory has been named benchmark/src to make it fit the Pallisade
directory structure layout better.

also note that the benchmark-master/src/re_std.cc file has been removed. 

-Dave Cousins 
