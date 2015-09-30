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

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
#CFLAGS := -g # -Wall
LIB := #-pthread -lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt
INC := -I include

#TaskLDFLAGS = -lpthread
#TimeLDFLAGS = -lm # -lrt

$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@echo " $(CC) $^ -o $(TARGET) $(LIB)"; $(CC) $^ -o $(TARGET) $(LIB)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	@mkdir -p $(BUILDDIR)/crypto
	@mkdir -p $(BUILDDIR)/encoding
	@mkdir -p $(BUILDDIR)/lattice
	@mkdir -p $(BUILDDIR)/math
	@mkdir -p $(BUILDDIR)/utils
#	@echo " $(BUILDDIR)"
	@echo " $(CC) $(CPPFLAGS) $(INC) -c -o $@ $<"; $(CC) $(CPPFLAGS) $(INC) -c -o $@ $<

clean:
	@echo " Cleaning..."; 
	@echo " $(RM) -r $(BUILDDIR) $(TARGET)"; $(RM) -r $(BUILDDIR) $(TARGET)

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
