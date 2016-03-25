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

CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g    ## undefine for single thread debug
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g -fopenmp  ##undefine for parallel operation
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w  -DNDEBUG  ##undefine for single thread speed
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w -fopenmp  ##undefine for parallel speed operation

SRCDIR := src
BUILDDIR := build
BUILDDIRMAIN := build/main
TARGETDIR := bin
HEADERS := src/*.h

SRCEXT := cpp
HDREXT := h
HDRDEEP := $(shell find $(SRCDIR) -mindepth 2 -type f -name *.$(HDREXT))
SOURCESDEEP := $(shell find $(SRCDIR) -mindepth 2 -type f -name *.$(SRCEXT)) 
SOURCESMAIN := $(shell find $(SRCDIR) -maxdepth 1 -type f -name *.$(SRCEXT))
TARGETSMAIN := $(patsubst $(SRCDIR)/%,$(TARGETDIR)/%,$(SOURCESMAIN:.$(SRCEXT)=))
OBJECTSDEEP := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCESDEEP:.$(SRCEXT)=.o))
OBJECTSMAIN := $(patsubst $(SRCDIR)/%,$(BUILDDIRMAIN)/%,$(SOURCESMAIN:.$(SRCEXT)=.o))

#LIB := -pthread #-lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt
LIB := -pthread -lgomp #-lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt
INC := -I include

all: alltargets apidocs alltesttargets allbenchmarktargets

.PHONEY: clean
clean: cleantargets cleantests cleandocs cleangnuheaders cleanbenchmarks

.PHONEY: cleangnuheaders
cleangnuheaders:
	rm -f */**/*.h.gch

include Makefile.targets
include Makefile.docs
include Makefile.test
include Makefile.benchmark
