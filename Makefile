#
#Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
#All rights reserved.
#Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
#met:
#1. Redistributions of source code must retain the above copyright
#notice, this list of conditions and the following disclaimer.
#2. Redistributions in binary form must reproduce the above copyright
#notice, this list of conditions and the following disclaimer in the
#documentation and/or other materials provided with the distribution.
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
#TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
#PARTICULAR PURPOSE ARE DISCLAIMED.
#IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
#ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#POSSIBILITY OF SUCH DAMAGE.
#


################
# Makefile contains core definitions and then includes  build instructions
# for making all the palisade components
################


CC := g++ # This is the main compiler

# NOTE select the appropriate set of CPPFLAGS 
# most code is checked into git with the first line active
CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g## undefine for single thread debug operation
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g -fopenmp  ##undefine for parallel debug operation
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w  -DNDEBUG  ##undefine for single thread best performance operation
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w -fopenmp  ##undefine for parallel best performance operation

#fundamental locations in the palisade directory structure
#sources for all palisade code
SRCDIR := src
#build directory
BUILDDIR := build
#bin directory
BINDIR := bin
#sources for demonstration files
DEMODIR := src/demo
#sources for palisade library
SRCLIBDIR := src/lib
EXTLIBDIR := lib

# extentions for source and header files
SRCEXT := cpp
HDREXT := h



#$(wildcard $(addsuffix *.cpp,$(DEMODIRS)/))
#objects := $(patsubst %.cpp,%.o,$(sources))

$(objects) : %.o : %.cpp

EXTLIB := -pthread -lgomp #-lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt
INC := -I include

#the name of the shared object library for palisade objects.  
SOLIB := PALISADE


# run make for all components. you can run any individual component separately
#  by invoking   "make alltargets"  for example
# each corresponding makefile will make the allxxxx target
all: alldemos alltargets alltesttargets allbenchmarktargets apidocs 

# clean up all components. you can clean any individual compoenent separately
#  by invoking   "make cleantargets"  for example
# each corresponding makefile will make the cleanxxxx target
.PHONEY: clean
clean: cleandemos cleantargets  cleantests cleanbenchmarks cleandocs 
#cleangnuheaders 


# TODO: document what cleangnuheaders does
.PHONEY: cleangnuheaders
cleangnuheaders:
	rm -f */**/*.h.gch


#the following includes the precise makefiles for each palisade component.

include Makefile.targets	#builds the palisade shared library
include Makefile.demos		#builds the demo executables
include Makefile.test		#builds the test framework
include Makefile.benchmark	#builds the benchmark framework
include Makefile.docs		#populates doxgen documentation
