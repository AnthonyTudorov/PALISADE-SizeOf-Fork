CPPFLAGS += -Wall -O3 -std=gnu++11 -w -g

TaskLDFLAGS = -lpthread
TimeLDFLAGS = -lm -lrt

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

NTRU-PRE-Key: $(MAINDEPS) Source_key.o
	$(CXX) -o $@ $^ $(TaskLDFLAGS) $(TimeLDFLAGS)

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
