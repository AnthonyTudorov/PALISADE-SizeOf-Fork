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
#CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g
#flags for debusing
CPPFLAGS += -Wall -O0 -std=gnu++11 -w -g

SRCDIR := src
BUILDDIR := build
TARGETDIR := bin
HEADERS := src/*.h

#MAINSOURCES := src/Source.cpp src/Source_AHE.cpp
TESTTARGET := test/bin/tests

SRCEXT := cpp
SOURCESDEEP := $(shell find $(SRCDIR) -mindepth 2 -type f -name *.$(SRCEXT))
SOURCESMAIN := $(shell find $(SRCDIR) -maxdepth 1 -type f -name *.$(SRCEXT))
TARGETSMAIN := $(patsubst $(SRCDIR)/%,%,$(SOURCESMAIN:.$(SRCEXT)=))
OBJECTSDEEP := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCESDEEP:.$(SRCEXT)=.o))
#SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
#OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
#CFLAGS := -g # -Wall
LIB := -pthread #-lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt
INC := -I include

#TaskLDFLAGS = -lpthread
#TimeLDFLAGS = -lm # -lrt

#all: alltargets apidocs alltesttargets runtests
#dbc: runtests takes very long. so should not be automatically run
all: alltargets apidocs alltesttargets allbenchmarktargets

.PHONY:targets
targets: alltargets alltesttargets allbencmarktargets

.PHONY:alltargets
alltargets: $(TARGETSMAIN)

.PHONY:alltesttargets
alltesttargets: $(TESTTARGET)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	@mkdir -p $(BUILDDIR)/crypto
	@mkdir -p $(BUILDDIR)/obfuscate
	@mkdir -p $(BUILDDIR)/encoding
	@mkdir -p $(BUILDDIR)/lattice
	@mkdir -p $(BUILDDIR)/math
	@mkdir -p $(BUILDDIR)/math/cpu8bit
	@mkdir -p $(BUILDDIR)/math/cpu_int
	@mkdir -p $(BUILDDIR)/multilinearmap
	@mkdir -p $(BUILDDIR)/utils
#	@echo " $@"
#	@echo " $<"
#	@echo " $(BUILDDIR)"
#	@echo " $(SRCDIR)"
	@echo " $(CC) $(CPPFLAGS) $(INC) -c -o $@ $< "; $(CC) $(CPPFLAGS) $(INC) -c -o $@ $<

$(TARGETSMAIN): $(OBJECTSDEEP)
	@echo " Target: $(TARGETDIR)/$@"
#	@echo " $^"
	@mkdir -p $(TARGETDIR)
	@echo " $(CC) $(CPPFLAGS) $(INC) -c -o $(BUILDDIR)/$@.o $(SRCDIR)/$@.$(SRCEXT)"; $(CC) $(CPPFLAGS) $(INC) -c -o $(BUILDDIR)/$@.o $(SRCDIR)/$@.$(SRCEXT)
	@echo " $(CC) $^ $(BUILDDIR)/$@.o -o $(TARGETDIR)/$@ $(LIB)"; $(CC) $^ $(BUILDDIR)/$@.o -o $(TARGETDIR)/$@ $(LIB)
#	@echo "rm $(BUILDDIR)/$@.o"; rm $(BUILDDIR)/$@.o

TESTSRCDIR := test/src
TESTBUILDDIR := test/build
TESTTARGETDIR := test/bin
TESTTARGET := test/bin/tests

#DBC: what is the following for?
check: $(TESTTARGET)   
	$(TESTTARGET)

LIBSOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT) | xargs grep -L "main()")
LIBOBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(LIBSOURCES:.$(SRCEXT)=.o))



TESTSOURCES := $(shell find $(TESTSRCDIR) -type f -name *.$(SRCEXT))
TESTOBJECTS := $(patsubst $(TESTSRCDIR)/%,$(TESTBUILDDIR)/%,$(TESTSOURCES:.$(SRCEXT)=.o))
TESTLIB := -pthread #-lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt

TESTLIBSRCEXT := cc
TESTLIBSRCDIR := test/include/gtest
TESTLIBSOURCES := $(shell find $(TESTLIBSRCDIR) -type f -name *.$(TESTLIBSRCEXT))
TESTLIBOBJECTS := $(patsubst $(TESTLIBSRCDIR)/%,$(TESTBUILDDIR)/%,$(TESTLIBSOURCES:.$(TESTLIBSRCEXT)=.o))

# Points to the root of Google Test, relative to where this file is.
# Remember to tweak this if you move this file.
#GTEST_DIR = test/include

# All Google Test headers.  Usually you shouldn't change this
# definition.
GTEST_HEADERS =	test/include/gtest/gtest.h
#		$(GTEST_DIR)/include/gtest/gtest-death-test.h \
#		$(GTEST_DIR)/include/gtest/gtest-message.h \
#		$(GTEST_DIR)/include/gtest/gtest-printers.h \
#		$(GTEST_DIR)/include/gtest/gtest-spi.h \
#		$(GTEST_DIR)/include/gtest/gtest-typed-test.h \
#		$(GTEST_DIR)/include/gtest/gtest.h \
#		$(GTEST_DIR)/include/gtest/gtest-param-test.h \
#		$(GTEST_DIR)/include/gtest/gtest_prod.h \
#		$(GTEST_DIR)/include/gtest/gtest-test-part.h \
##GTEST_HEADERS =	$(GTEST_DIR)/include/gtest/*.h \
#               $(GTEST_DIR)/include/gtest/internal/*.h

$(TESTBUILDDIR)/%.o: $(TESTLIBSRCDIR)/%.$(TESTLIBSRCEXT)
	@mkdir -p $(@D)
#	@echo " $(BUILDDIR)"
#	@echo "------ $(CC) $(CPPFLAGS) $(INC) $(TESTLIB) -c -o $@ $<"; $(CC) $(CPPFLAGS) $(INC) $(TESTLIB) -c -o $@ $<
	@echo "$(CC) $(CPPFLAGS) $(INC) $(TESTLIB) -c -o $@ $<"; $(CC) $(CPPFLAGS) $(INC) $(TESTLIB) -c -o $@ $<
	@echo "ar -rv $(TESTBUILDDIR)/libgtest.a $@"; ar -rv $(TESTBUILDDIR)/libgtest.a $@

$(TESTBUILDDIR)/%.o: $(TESTSRCDIR)/%.$(SRCEXT)
	@mkdir -p $(@D)
#	@echo " $(BUILDDIR)"
	@echo " $(CC) $(CPPFLAGS) $(INC) $(TESTLIB) -c -o $@ $<"; $(CC) $(CPPFLAGS) $(INC) $(TESTLIB) -c -o $@ $<

$(TESTTARGET): $(TESTOBJECTS) $(TESTLIBOBJECTS) $(LIBOBJECTS)
	@echo "$(TESTLIBSRCEXT)"
	@echo "$(TESTLIBSRCDIR)"
	@echo "$(TESTLIBSOURCES)"
	@echo "$(TESTLIBOBJECTS)"
	@echo " Linking..."
	@mkdir -p $(TESTTARGETDIR)
	@echo " $(CC) $^ $(TESTLIB) $(TESTBUILDDIR)/libgtest.a -o $(TESTTARGET)"; $(CC) $^ $(TESTLIB) $(TESTBUILDDIR)/libgtest.a -o $(TESTTARGET)

.PHONY: runtests
runtests: $(TESTTARGET)
	$(TESTTARGET)

.PHONEY: apidocs
apidocs:
	doxygen lbcrypto-doxy-config

.PHONEY: clean
clean: cleantargets cleantests cleandocs cleangnuheaders cleanbenchmarks

.PHONEY: cleantargets
cleantargets:
	@echo " Cleaning...";
	@echo " $(RM) -r $(BUILDDIR) $(TARGETDIR)"; $(RM) -r $(BUILDDIR) $(TARGETDIR)

.PHONEY: cleantests
cleantests:
	@echo " Cleaning...";
	@echo " $(RM) -r $(TESTBUILDDIR) $(TESTTARGETDIR)"; $(RM) -r $(TESTBUILDDIR) $(TESTTARGETDIR)

.PHONEY: cleandocs
cleandocs:
	rm -rf doc/apidocs

.PHONEY: cleangnuheaders
cleangnuheaders:
	rm -f */**/*.h.gch

#all: $(TARGETS)

#\
#ideals.o\
#inttypes.o\
#pubkeylp.o

#sipher-v10-01-debug: $(MAINDEPS) debug.o
#	$(CC) -o $@ $^ $(TaskLDFLAGS) $(TimeLDFLAGS)

#NTRU-PRE: $(MAINDEPS) Source.o
#	$(CXX) -o $@ $^ $(TaskLDFLAGS) $(TimeLDFLAGS)

#NTRU-PRE-Key: $(MAINDEPS) Source_key.o
#	$(CXX) -o $@ $^ $(TaskLDFLAGS) $(TimeLDFLAGS)




#.PHONEY: publishapi
#publishapi: apidocs
#	rm -rf /opt/doxygen/arms-nfd && mv apidocs/html /opt/doxygen/arms-nfd

#.PHONEY: clean
#clean: cleandocs
#	rm -f *.o $(TARGETS) *~ .depends

#.PHONEY: depends
#depends: .depends
#.depends:
#	@echo -n "Generating dependencies..."
#	@gcc -E -MM *.o > $@
#	@echo "Done."
#
#-include .depends

include Makefile.benchmark
