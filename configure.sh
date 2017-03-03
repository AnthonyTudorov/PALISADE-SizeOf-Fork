echo command creates a makefile to be used for different platforms

KernelName=`uname -s`

echo $OS
echo $KernelName

### must locate compiler, boost

if [ "$OS" = "Windows_NT" ]
then
	build=mingw64
	BOOSTINCLUDE="-I C:/boost_1_60_0"
	BOOSTLIB="-L C:/boost_1_60_0/stage/lib/"
	OMPINCLUDE=""
	CC="g++ # This is the main compiler"
	CPPSTD="-std=gnu++11"
	LIBCMD="-s -shared -Wl,--subsystem,windows "
	LIBSUFFIX=".dll"
	EXESUFFIX=".exe

	MINGWREGEX="-Lc:/Mingw64/mingw64/opt/lib -lregex -lshlwapi

	RDYNAMIC="

	JNIBUILD=" -I "C:/Program Files/java/jdk1.8.0_91/include" -I "C:/Program Files/java/jdk1.8.0_91/include/win32"
	JNILIB := PalisadeCryptoWrapper.dll

	PYINCLUDE="-I C:/Mingw64/mingw64/opt/include/python2.7
	LIBPYTHON="-L C:/Mingw64/mingw64/opt/bin -lpython2.7 
elif [ "$KernelName" = "Linux" ]
then
	build=Linux
## for linux

##BOOSTINCLUDE := -I /afs/cad/linux/boost-1.60-sl6/include/
BOOSTINCLUDE := 

OMPINCLUDE := 

CC := g++ # This is the main compiler
CPPSTD := -std=gnu++11


LIBSUFFIX := .so
LIBCMD := -fPIC -shared -Wl,--export-dynamic

RDYNAMIC := -rdynamic

JNIBUILD :=  
JNILIB := libPalisadeCryptoWrapper.so

PYINCLUDE := -I/usr/include/python2.7
LIBPYTHON := -lpython2.7 
elif [ "$KernelName" = "Darwin" ]
then
	build=MacOS
## for mac OSx

BOOSTINCLUDE := -I /boost_1_61_0
BOOSTLIB := -L /boost_1_61_0/stage/lib/
OMPINCLUDE := -I /opt/local/include/libomp -fopenmp
#CPPSTD := -std=gnu++0x
CC := clang++ # This is the main compiler
CPPSTD := -std=c++11 -stdlib=libc++

LIBSUFFIX := .dylib
LIBCMD := -fopenmp -dynamiclib
#-undefined suppress -flat_namespace

RDYNAMIC := 

JNIBUILD :=  
JNILIB := libPalisadeCryptoWrapper.jnilib
JNILINKPARM := -framework JavaVM

PYINCLUDE := $(shell python-config --include)
LIBPYTHON := -lpython2.7 
elif [ "$KernelName" = "CYGWIN_NT" }
then
	build=cyg
fi

exit

else

    ifeq ($(UNAME_S),Darwin)
        #CCFLAGS += -D OSX
	include Makefile.mac
    endif

    ifeq ($(UNAME_S),CYGWIN_NT-6.1)
        #CCFLAGS += -D CYGWIN
	include Makefile.mingw
    endif

  #  UNAME_P := $(shell uname -p)
  #  ifeq ($(UNAME_P),x86_64)
  #      CCFLAGS += -D AMD64
  #  endif
  #  ifneq ($(filter %86,$(UNAME_P)),)
  #      CCFLAGS += -D IA32
  #  endif
  #  ifneq ($(filter arm%,$(UNAME_P)),)
  #      CCFLAGS += -D ARM
  #  endif
endif

include Makefile.common

# NOTE select the appropriate set of CPPFLAGS 
# most code is checked into git with the first line active

#CPPFLAGS += -Wall $(CPPSTD) -w -g ## undefine for single thread debug NO OPTIMIZATION operation
#CPPFLAGS += -Wall -O3 $(CPPSTD) -w -g ## undefine for single thread debug operation
#CPPFLAGS += -Wall -O3 $(CPPSTD) -w -g -fopenmp  ##undefine for parallel debug operation
#CPPFLAGS += -Wall -O3 $(CPPSTD) -w  -DNDEBUG  -pg ##undefine for single thread best performance operation with gprof profiling 


#main best performance configuration for parallel operation - cross-platform
CPPFLAGS += -Wall -O3 $(CPPSTD) -w -fopenmp ##undefine for parallel best performance operation with debug
#CPPFLAGS += -Wall -O3 $(CPPSTD) -w -fopenmp -m64 -DNDEBUG  ##undefine for parallel best performance operation with no debug

#THE OPTIONS BELOW SHOULD BE USED WITH CARE AS THEY USE A LOT OF AGGRESSIVE OPTIMIZATION OPTIONS
#CPPFLAGS += -Wall $(CPPSTD) -w  -DNDEBUG -m64 -Ofast -flto -march=native -funroll-loops ##undefine for single thread best performance operation
#CPPFLAGS += -Wall $(CPPSTD) -w  -DNDEBUG -m64 -Ofast -flto -march=native -funroll-loops -fopenmp ##undefine for multithread really best performance operation
#CPPFLAGS += -Wall $(CPPSTD) -w  -m64 -Ofast -flto -march=native -funroll-loops -fopenmp -DNDEBUG ##undefine for multithread really best performance operation
#CPPFLAGS += -Wall $(CPPSTD) -w  -m64 -Ofast -flto -march=native -funroll-loops -fopenmp ##undefine for multithread really best performance operation


TEST_LIB := -pthread -lgomp 


#build directory
BUILDDIR := build

#bin directory
BINDIR := bin

#sources for palisade library
SRCLIBDIR := src/lib
EXTLIBDIR := bin/lib
EXTTESTDIR := bin/unittest
EXTDEMODIR := bin/demo

# extentions for source and header files
SRCEXT := cpp
HDREXT := h

$(objects) : %.o : %.cpp


EXTLIB := -L$(EXTLIBDIR) -lpthread -lgomp -pg #-lmongoclient -L lib -lboost_thread-mt -lboost_filesystem-mt -lboost_system-mt ## include profiling
INC := -I src/core/lib -I src/pke/lib -I src/trapdoor/lib -I test $(OMPINCLUDE) $(BOOSTINCLUDE)


#the name of the shared object library for palisade objects.  
PALISADECORELIB := libPALISADEcore$(LIBSUFFIX)
PALISADEPKELIB := libPALISADEpke$(LIBSUFFIX)
PALISADETRAPDOORLIB := libPALISADEtrapdoor$(LIBSUFFIX)
PALISADEPYLIB := pycrypto$(LIBSUFFIX)

# run make for all components. you can run any individual component separately
#  by invoking   "make alltargets"  for example
# each corresponding makefile will make the allxxxx target
all: allcore allpke alltrapdoor apidocs 

alljava: allcore allpke jwrapper

allpython: allcore allpke alltrapdoor pywrapper

alldemos: allcoredemos allpkedemos alltrapdoordemos

testall: testcore testpke testtrapdoor

# clean up all components. you can clean any individual compoenent separately
#  by invoking   "make cleantargets"  for example
# each corresponding makefile will make the cleanxxxx target
.PHONEY: clean
clean: cleancore cleanpke cleantrapdoor cleandocs 
	@echo 'Cleaning top level autogenerated directories'
	$(RM) -rf bin build

include Makefile.core
include Makefile.pke
include Makefile.trapdoor
include Makefile.wrapper
include Makefile.benchmark     #builds the benchmark framework
include Makefile.docs          #populates doxgen documentation

