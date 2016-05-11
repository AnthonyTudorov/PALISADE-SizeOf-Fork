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

CC := g++ # This is the main compiler

#NOTE select the appropriate set of CPPFLAGS 
# most code is checked into git with the first line active
CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g## undefine for single thread debug operation
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g -fopenmp  ##undefine for parallel debug operation
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w  -DNDEBUG  ##undefine for single thread best performance operation
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w -fopenmp  ##undefine for parallel best performance operation

SRCDIR := src
BUILDDIR := build
BINDIR := bin
DEMODIR := src/demo
SRCLIBDIR := src/lib
EXTLIBDIR := lib

SRCEXT := cpp
HDREXT := h

#$(wildcard $(addsuffix *.cpp,$(DEMODIRS)/))
#objects := $(patsubst %.cpp,%.o,$(sources))

$(objects) : %.o : %.cpp

EXTLIB := -pthread -lgomp #-lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt
INC := -I include
SOLIB := PALISADE

all: alldemos alltargets
# apidocs alltesttargets allbenchmarktargets

.PHONEY: clean
clean: cleandemos cleantargets 
# cleantests cleandocs cleangnuheaders cleanbenchmarks

.PHONEY: cleangnuheaders
cleangnuheaders:
	rm -f */**/*.h.gch

include Makefile.targets
include Makefile.demos
#include Makefile.docs
#include Makefile.test
#include Makefile.benchmark
