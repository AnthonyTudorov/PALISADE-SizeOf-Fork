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
CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g

# identify the directory where the source files are taken from.
SRCDIR := src
# identify the directory where the .o build files are placed.
BUILDDIR := build
# identify the directory where the build main files are placed.  We assume there is not a 
# main directory in the source directory.
BUILDDIRMAIN := build/main
# identify the directory where the binary files are placed
TARGETDIR := bin
# identify the header files.
HEADERS := src/*.h

# identify the extension of the source files.
SRCEXT := cpp
# identify the source files which do not have mains.  We assume this is everything in child directories of the source directory.
SOURCESDEEP := $(shell find $(SRCDIR) -mindepth 2 -type f -name *.$(SRCEXT))
# identify the source files which have mains.  We assume this is everything in root of the source directory.
SOURCESMAIN := $(shell find $(SRCDIR) -maxdepth 1 -type f -name *.$(SRCEXT))
# identify the main targets.  We assume this is everything built from the source directory swapped for the target directory in the source main category.
TARGETSMAIN := $(patsubst $(SRCDIR)/%,$(TARGETDIR)/%,$(SOURCESMAIN:.$(SRCEXT)=))
# identify the dependency objects.  We assume this is everything built from the source directory not in the source root swapped for the target directory in the source main category.
OBJECTSDEEP := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCESDEEP:.$(SRCEXT)=.o))
# identify the main objects.  We assume this is everything built from the source directory in the source root swapped for the target directory in the source main category.
OBJECTSMAIN := $(patsubst $(SRCDIR)/%,$(BUILDDIRMAIN)/%,$(SOURCESMAIN:.$(SRCEXT)=.o))

LIB := -pthread #-lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt
INC := -I include

# make all builds everything - targets, docs, tests and benchmarks, respectively.
all: alltargets apidocs alltesttargets allbenchmarktargets

.PHONEY: clean
# make clean deletes everything - targets, tests, docs, gnu headers and benchmarks, respectively.
clean: cleantargets cleantests cleandocs cleangnuheaders cleanbenchmarks

.PHONEY: cleangnuheaders
cleangnuheaders:
	rm -f */**/*.h.gch

# Makefile.targets include the primary make targets to build the primary source files.
include Makefile.targets
# Makefile.targets include the make targets to build the documentation in doxygen.
include Makefile.docs
# Makefile.targets include the make targets to build the unit tests.
include Makefile.test
# Makefile.targets include the make targets to build the benchmarks.
include Makefile.benchmark
