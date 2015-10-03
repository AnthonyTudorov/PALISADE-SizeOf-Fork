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

CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g

TaskLDFLAGS = -lpthread
TimeLDFLAGS = -lm # -lrt

TARGETS= NTRU-PRE
all: $(TARGETS)

MAINDEPS= binint.o\
binmat.o\
binvect.o\
mempool.o\
nbtheory.o\
dtstruct.o\
transfrm.o\
distrgen.o\
lwecrypt.o\
lwepre.o\
il2n.o\
utilities.o
#\
#ideals.o\
#inttypes.o\
#pubkeylp.o

#sipher-v10-01-debug: $(MAINDEPS) debug.o
#	$(CC) -o $@ $^ $(TaskLDFLAGS) $(TimeLDFLAGS)

NTRU-PRE: $(MAINDEPS) Source.o
	$(CXX) -o $@ $^ $(TaskLDFLAGS) $(TimeLDFLAGS)

#NTRU-PRE-Key: $(MAINDEPS) Source_key.o
#	$(CXX) -o $@ $^ $(TaskLDFLAGS) $(TimeLDFLAGS)

.PHONEY: apidocs
apidocs:
	doxygen lbcrypto-doxy-config

.PHONEY: cleandocs
cleandocs:
	rm -rf apidocs

.PHONEY: publishapi
publishapi: apidocs
	rm -rf /opt/doxygen/arms-nfd && mv apidocs/html /opt/doxygen/arms-nfd

.PHONEY: clean
clean: cleandocs
	rm -f *.o $(TARGETS) *~ .depends

.PHONEY: depends
depends: .depends
.depends:
	@echo -n "Generating dependencies..."
	@gcc -E -MM *.o > $@
	@echo "Done."

-include .depends
