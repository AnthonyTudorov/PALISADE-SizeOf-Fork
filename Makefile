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

SRCDIR := src
BUILDDIR := build
TARGET := bin/NTRU-PRE
HEADERS := src/*.h

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
#CFLAGS := -g # -Wall
LIB := #-pthread -lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt
INC := -I include

#TaskLDFLAGS = -lpthread
#TimeLDFLAGS = -lm # -lrt

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	@mkdir -p $(BUILDDIR)/crypto
	@mkdir -p $(BUILDDIR)/encoding
	@mkdir -p $(BUILDDIR)/lattice
	@mkdir -p $(BUILDDIR)/math
	@mkdir -p $(BUILDDIR)/math/cpu8bit
	@mkdir -p $(BUILDDIR)/utils
#	@echo " $(BUILDDIR)"
	@echo " $(CC) $(CPPFLAGS) $(INC) -c -o $@ $<"; $(CC) $(CPPFLAGS) $(INC) -c -o $@ $<

$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@echo " $(CC) $^ -o $(TARGET) $(LIB)"; $(CC) $^ -o $(TARGET) $(LIB)

TESTSRCDIR := test/src
TESTBUILDDIR := test/build
TESTTARGET := test/bin/tests

LIBSOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT) | xargs grep -L "main()")
LIBOBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(LIBSOURCES:.$(SRCEXT)=.o))

TESTSOURCES := $(shell find $(TESTSRCDIR) -type f -name *.$(SRCEXT))
TESTOBJECTS := $(patsubst $(TESTSRCDIR)/%,$(TESTBUILDDIR)/%,$(TESTSOURCES:.$(SRCEXT)=.o))
TESTLIB := -lgtest -lgtest_main -lpthread#-pthread -lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt

# Points to the root of Google Test, relative to where this file is.
# Remember to tweak this if you move this file.
GTEST_DIR = /usr/local

# All Google Test headers.  Usually you shouldn't change this
# definition.
GTEST_HEADERS =	$(GTEST_DIR)/include/gtest/gtest.h \
		$(GTEST_DIR)/include/gtest/gtest-death-test.h \
		$(GTEST_DIR)/include/gtest/gtest-message.h \
		$(GTEST_DIR)/include/gtest/gtest-printers.h \
		$(GTEST_DIR)/include/gtest/gtest-spi.h \
		$(GTEST_DIR)/include/gtest/gtest-typed-test.h \
		$(GTEST_DIR)/include/gtest/gtest.h \
		$(GTEST_DIR)/include/gtest/gtest-param-test.h \
		$(GTEST_DIR)/include/gtest/gtest_prod.h \
		$(GTEST_DIR)/include/gtest/gtest-test-part.h \
#GTEST_HEADERS =	$(GTEST_DIR)/include/gtest/*.h \
               $(GTEST_DIR)/include/gtest/internal/*.h

$(TESTBUILDDIR)/%.o: $(TESTSRCDIR)/%.$(SRCEXT)
	@mkdir -p $(TESTBUILDDIR)
#	@echo " $(BUILDDIR)"
	@echo " $(CC) $(CPPFLAGS) $(INC) $(TESTLIB) -c -o $@ $<"; $(CC) $(CPPFLAGS) $(INC) $(TESTLIB) -c -o $@ $<

$(TESTTARGET): $(TESTOBJECTS) $(GTEST_HEADERS)
	@echo " Linking..."
	@echo " $(CC) $(LIBOBJECTS) $^ -o $(TESTTARGET) $(TESTLIB)"; $(CC) $(LIBOBJECTS) $^ -o $(TESTTARGET) $(TESTLIB)

clean:
	@echo " Cleaning..."; 
	@echo " $(RM) -r $(BUILDDIR) $(TARGET) $(TESTBUILDDIR) $(TESTTARGET)"; $(RM) -r $(BUILDDIR) $(TARGET) $(TESTBUILDDIR) $(TESTTARGET)

cleantests:
	@echo " Cleaning..."; 
	@echo " $(RM) -r $(TESTBUILDDIR) $(TESTTARGET)"; $(RM) -r $(TESTBUILDDIR) $(TESTTARGET)

.PHONEY: clean

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

.PHONEY: apidocs
apidocs:
	doxygen lbcrypto-doxy-config

.PHONEY: cleandocs
cleandocs:
	rm -rf doc/apidocs

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
