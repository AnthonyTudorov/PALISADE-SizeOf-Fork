cmake_minimum_required (VERSION 3.4)

project (PALISADE C CXX)

set(BUILD_STATIC "NO") # set to yes to build static libs and apps
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if("${WITH_NTL}" STREQUAL "true")
	message("NTL is turned ON")
endif()

set(TAR "tar")
if(APPLE)
	set(TAR "gtar")
endif()

if(APPLE)
	set(OPENMP_LIBRARIES "/usr/local/opt/libomp/lib")
	set(OPENMP_INCLUDES "/usr/local/opt/libomp/include")
endif()

OPTION (USE_OpenMP "Use OpenMP to enable <omp.h>" ON)

# Set OpenMP configuration manually for MacOS
if(APPLE AND USE_OpenMP)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
       set(OpenMP_C_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
       set(OpenMP_C_LIB_NAMES "libomp")
       set(OpenMP_libomp_LIBRARY ${OpenMP_C_LIB_NAMES})
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
       set(OpenMP_CXX_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
       set(OpenMP_CXX_LIB_NAMES "libomp")
       set(OpenMP_libomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
    endif()
endif()
	
### several of the third-party tools use auto-make and autoconf
### we need to make sure that they are installed
execute_process(COMMAND autogen --version OUTPUT_VARIABLE AUTOGEN_VER)
# execute_process in MINGW by default does not run in a shell
if(MINGW)
	execute_process(COMMAND sh autoconf --version OUTPUT_VARIABLE AUTOCONF_VER)
else()
	execute_process(COMMAND autoconf --version OUTPUT_VARIABLE AUTOCONF_VER)	
endif()

#string(LENGTH "${AUTOGEN_VER}" AUTOGEN_VER_LEN)
string(LENGTH "${AUTOCONF_VER}" AUTOCONF_VER_LEN)

#if( ${AUTOGEN_VER_LEN} EQUAL 0 )
#	message(SEND_ERROR "Autogen is not installed.")
#endif()
if( ${AUTOCONF_VER_LEN} EQUAL 0 )
	message(SEND_ERROR "Autoconf is not installed.")
endif()

set(PALISADE_VERSION_MAJOR 1)
set(PALISADE_VERSION_MINOR 6)
set(PALISADE_VERSION_PATCH 0)
set(PALISADE_VERSION ${PALISADE_VERSION_MAJOR}.${PALISADE_VERSION_MINOR}.${PALISADE_VERSION_PATCH})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    # require at least gcc 6.1
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6.1)
        message(FATAL_ERROR "GCC version must be at least 6.1!")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    # require at least clang 6
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6)
        message(FATAL_ERROR "Clang version must be at least 6!")
    endif()
else()
	message(FATAL_ERROR  "You are using ${CMAKE_CXX_COMPILER_ID} version ${CMAKE_CXX_COMPILER_VERSION}, which is unsupported.")
endif()

message("***** INSTALL IS AT ${CMAKE_INSTALL_PREFIX}; to change, run cmake with -DCMAKE_INSTALL_PREFIX=/your/path")
set (CMAKE_INSTALL_MESSAGE LAZY)

# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
IF("${isSystemDir}" STREQUAL "-1")
   SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
ENDIF("${isSystemDir}" STREQUAL "-1")

set(CMAKE_CXX_STANDARD 11)
if(APPLE)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

# Added -Wno-parentheses -Wno-pessimizing-move for compatibility with g++ >= v9.0
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
		set (IGNORE_WARNINGS "")
	else()
		set (IGNORE_WARNINGS "-Wno-parentheses -Wno-pessimizing-move")
	endif()
endif()

set(COMPILEFLAGS "-Wall -Werror -O3 -DPALISADE_VERSION=${PALISADE_VERSION} ${IGNORE_WARNINGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILEFLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMPILEFLAGS}")

find_package (OpenMP)

if( APPLE AND USE_OpenMP)
	include_directories("${OPENMP_INCLUDES}")
	link_directories("${OPENMP_LIBRARIES}")
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
endif()

if (OpenMP_CXX_FOUND)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

if (OpenMP_C_FOUND)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
endif()

find_package (Git REQUIRED)

find_package (Doxygen QUIET COMPONENTS dot)
if (DOXYGEN_FOUND)

    add_custom_target( apidocs 
        COMMAND sh -c "( cat ${CMAKE_CURRENT_SOURCE_DIR}/lbcrypto-doxy-config && echo PROJECT_NUMBER=${PALISADE_VERSION} ) | ${DOXYGEN_EXECUTABLE} -"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )

else (DOXYGEN_FOUND)
  message("Doxygen and dot (from graphviz) need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)

include (ExternalProject)

# third party directories
set( THIRDPARTYDIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party )
include_directories( ${THIRDPARTYDIR}/include )

### Handle third-party CEREAL
include_directories( ${THIRDPARTYDIR}/cereal/include )

include_directories( src )
set (SUBMAKEFILES core pke trapdoor abe signature)
foreach( dir ${SUBMAKEFILES} )
	include_directories( src/${dir}/lib )
endforeach( dir )

include_directories( third-party/google-test/googletest third-party/google-test/googletest/include )
include_directories( ${CMAKE_CURRENT_BINARY_DIR}/third-party/include )

## for tests
set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)

### handle third-party gmp
### note on Windows we build static

set(GMPSRCDIR ${THIRDPARTYDIR}/distros/gmp-6.1.2)
set(GMPLIBDIR ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib)
#if (MINGW)
#	set(GMPLIBFILE ${GMPLIBDIR}/libgmp${CMAKE_STATIC_LIBRARY_SUFFIX})
#	set(GMPLIBFILE_STATIC ${GMPLIBDIR}/libgmp${CMAKE_STATIC_LIBRARY_SUFFIX})
#else()
	set(GMPLIBFILE ${GMPLIBDIR}/libgmp${CMAKE_SHARED_LIBRARY_SUFFIX})
#	set(GMPLIBFILE_STATIC ${GMPLIBDIR}/libgmp${CMAKE_STATIC_LIBRARY_SUFFIX})
#endif()
set(GMPCONF ${GMPSRCDIR}/config.h)

# unpack gmp distro

add_custom_target(
	gmp_unpack
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf gmp-6.1.2.tar.lz
	COMMAND cd ${GMPSRCDIR} && ./configure --host=${CROSS_TRIPLE} --prefix=${CMAKE_CURRENT_BINARY_DIR}/third-party --disable-static --enable-shared
)

add_custom_target(
	gmp_clobber
	COMMAND rm -fr ${THIRDPARTYDIR}/distros/gmp-6.1.2
	COMMAND rm -f "${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libgmp*"
	COMMAND rm -f "${CMAKE_CURRENT_BINARY_DIR}/third-party/include/gmp.h"
	COMMAND rm -fr "${CMAKE_CURRENT_BINARY_DIR}/third-party/share/info"
)

add_custom_target(
	gmp_all
	COMMAND make 
	COMMAND make install
	WORKING_DIRECTORY ${GMPSRCDIR}
)

#add_library(gmp_static STATIC IMPORTED GLOBAL)
#set_target_properties(gmp_static PROPERTIES IMPORTED_LOCATION ${GMPLIBFILE_STATIC})
add_library(gmp SHARED IMPORTED GLOBAL)
set_target_properties(gmp PROPERTIES IMPORTED_LOCATION ${GMPLIBFILE})

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib DESTINATION .
	FILES_MATCHING PATTERN "libgmp.*" )

### Handle third-party libntl
### note on Windows we build static

set(NTLSRCDIR ${THIRDPARTYDIR}/distros/ntl-10.5.0/src)
set(NTLZIPNAME ntl-10.5.0.tar.gz)
set(NTLTARGET all)

set(NTLCONF ${NTLSRCDIR}/../include/NTL/config.h)
set(NTLLIBDIR ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib)
#if(MINGW)
#	set(NTLLIBFILE ${NTLLIBDIR}/libntl${CMAKE_STATIC_LIBRARY_SUFFIX})
#	set(NTLLIBFILE_STATIC ${NTLLIBDIR}/libntl${CMAKE_STATIC_LIBRARY_SUFFIX})
#else()
	set(NTLLIBFILE ${NTLLIBDIR}/libntl${CMAKE_SHARED_LIBRARY_SUFFIX})
#	set(NTLLIBFILE_STATIC ${NTLLIBDIR}/libntl${CMAKE_STATIC_LIBRARY_SUFFIX})
#endif()

# unpack ntl distro

add_custom_target(
	ntl_unpack
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf ${NTLZIPNAME}
	COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off
)

add_custom_target(
	ntl_unpack_nowizard
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf ${NTLZIPNAME}
	COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off TUNE=generic
)

add_custom_target(
	ntl_clobber
	COMMAND rm -fr ${THIRDPARTYDIR}/distros/ntl-10.5.0
	COMMAND rm -f "${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libntl*"
	COMMAND rm -fr "${CMAKE_CURRENT_BINARY_DIR}/third-party/include/NTL"
	COMMAND rm -fr "${CMAKE_CURRENT_BINARY_DIR}/third-party/share/doc"
)

add_custom_target(
	ntl_all
	COMMAND make
	COMMAND make install
	WORKING_DIRECTORY ${NTLSRCDIR}
)

#add_library(ntl_static STATIC IMPORTED GLOBAL)
#set_target_properties(ntl_static PROPERTIES IMPORTED_LOCATION ${NTLLIBFILE_STATIC})
add_library(ntl SHARED IMPORTED GLOBAL)
set_target_properties(ntl PROPERTIES IMPORTED_LOCATION ${NTLLIBFILE})

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib DESTINATION .
	FILES_MATCHING PATTERN "libntl.*" )

### Handle third-party gperftools for optional tcmalloc

add_custom_target(
	tcm
	COMMAND ./autogen.sh
	COMMAND ./configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/third-party --enable-minimal
	COMMAND make
	COMMAND make install
	WORKING_DIRECTORY ${THIRDPARTYDIR}/gperftools
)

add_custom_target(
	tcm_clean
	COMMAND rm -rf include/gperftools include/google lib/libtcmalloc_minimal* lib/pkgconfig/libtcmalloc* lib/pkgconfig/libprofiler.pc share/doc/gperftools 
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party
)

add_library(tcmalloc SHARED IMPORTED GLOBAL)
set_target_properties(tcmalloc PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libtcmalloc_minimal${CMAKE_SHARED_LIBRARY_SUFFIX})
add_library(tcmalloc_static SHARED IMPORTED GLOBAL)
set_target_properties(tcmalloc_static PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libtcmalloc_minimal${CMAKE_STATIC_LIBRARY_SUFFIX})

if(NOT APPLE)
	set(QUADMATHLIB -lquadmath)
endif()

if("${WITH_NTL}" STREQUAL "true")
	#if(MINGW)
	#	set(THIRDPARTYLIBS PUBLIC ntl_static PUBLIC gmp_static ${QUADMATHLIB})
	#else()
		set(THIRDPARTYLIBS PUBLIC ntl PUBLIC gmp ${QUADMATHLIB})
	#endif()
	#set(THIRDPARTYSTATICLIBS PUBLIC ntl_static PUBLIC gmp_static ${QUADMATHLIB})
	set(THIRDPARTYSTATICLIBS ${QUADMATHLIB})
	add_definitions(-DWITH_NTL)
else()
	#if(MINGW)
		set(THIRDPARTYLIBS ${QUADMATHLIB})
	#else()
	#	set(THIRDPARTYLIBS ${QUADMATHLIB})
	#endif()
	set(THIRDPARTYSTATICLIBS ${QUADMATHLIB})
endif()

### NEED TO ADD THIS LINE IF tcmalloc IS BEING USED
### set(THIRDPARTYLIBS PUBLIC ntl PUBLIC gmp PUBLIC tcmalloc)
###

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/include DESTINATION .)

if("${WITH_NTL}" STREQUAL "true")
add_custom_target(third-party ALL
 COMMAND [ ! -f  ${GMPLIBFILE} ] && echo ***ERROR*** Be sure to run \"make gmp_unpack\" and \"make gmp_all\" || [ ! -f  ${NTLLIBFILE} ] && echo ***ERROR*** Be sure to run \"make ntl_unpack\" and \"make ntl_all\" || echo
)
else()
add_custom_target(third-party ALL
)
endif()

### add each of the subdirs of src
add_subdirectory(src/core)
add_subdirectory(src/pke)
add_subdirectory(src/trapdoor)
add_subdirectory(src/abe)
add_subdirectory(src/signature)
add_subdirectory(android)

### build the google test handlers
add_subdirectory(third-party/google-test EXCLUDE_FROM_ALL)

### build the google benchmark handlers (just the parts we need)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Enable testing of the benchmark library." FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Enable installation of benchmark. (Projects embedding benchmark may want to turn this OFF.)" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Enable building the unit tests which depend on gtest" FORCE)
add_subdirectory(third-party/google-benchmark EXCLUDE_FROM_ALL)

add_subdirectory(benchmark)

## clobber cleans AND cleans the third-party stuff
add_custom_target( clobber DEPENDS gmp_clobber ntl_clobber
        COMMAND make clean
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target( testall
	DEPENDS core_tests pke_tests trapdoor_tests abe_tests signature_tests 
	COMMAND echo core: && unittest/core_tests -t
	COMMAND echo pke: && unittest/pke_tests -t
	COMMAND echo trapdoor: && unittest/trapdoor_tests -t
	COMMAND echo abe: && unittest/abe_tests -t
	COMMAND echo signature: && unittest/signature_tests -t
)
