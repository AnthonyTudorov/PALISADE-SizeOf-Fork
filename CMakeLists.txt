cmake_minimum_required (VERSION 3.4)

set(BUILD_STATIC "NO") # set to yes to build static libs and apps

set(TAR "tar")
if(APPLE)
	set(TAR "gnutar")
endif()

if(APPLE)
	set(CMAKE_C_COMPILER /opt/local/bin/clang)
	set(CMAKE_CXX_COMPILER /opt/local/bin/clang++)
	set(OPENMP_LIBRARIES "/opt/local/lib/openmpi-clang70/openmpi")
	set(OPENMP_INCLUDES "/opt/local/include/openmpi-clang70")
endif()

# Find OpenMP
if(APPLE AND USE_OpenMP)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(OpenMP_C "${CMAKE_C_COMPILER}")
        set(OpenMP_C_FLAGS "-fopenmp=libomp -Wno-unused-command-line-argument")
        set(OpenMP_C_LIB_NAMES "libomp" "libgomp" "libiomp5")
        set(OpenMP_libomp_LIBRARY ${OpenMP_C_LIB_NAMES})
        set(OpenMP_libgomp_LIBRARY ${OpenMP_C_LIB_NAMES})
        set(OpenMP_libiomp5_LIBRARY ${OpenMP_C_LIB_NAMES})
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      set(OpenMP_CXX "${CMAKE_CXX_COMPILER}")
      set(OpenMP_CXX_FLAGS "-fopenmp=libomp -Wno-unused-command-line-argument")
      set(OpenMP_CXX_LIB_NAMES "libomp" "libgomp" "libiomp5")
      set(OpenMP_libomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
      set(OpenMP_libgomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
      set(OpenMP_libiomp5_LIBRARY ${OpenMP_CXX_LIB_NAMES})
    endif()
endif()

project (PALISADE C CXX)

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
    message(FATAL_ERROR  "You are using an unsupported compiler! Compilation has only been tested with Clang and GCC.")
endif()

set (CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/installed)
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

set (CMAKE_CXX_STANDARD 11)
if(APPLE)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

set(COMPILEFLAGS "-g -Wall -Werror -O3")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILEFLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMPILEFLAGS}")

OPTION (USE_OpenMP "Use OpenMP to enamble <omp.h>" ON)

if(USE_OpenMP)
	include(FindOpenMP)
endif()

if (OPENMP_FOUND)
	if( APPLE )
		include_directories("${OPENMP_INCLUDES}")
		link_directories("${OPENMP_LIBRARIES}")
	endif()

	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

find_package (Git REQUIRED)

find_package (Doxygen REQUIRED dot)
if (DOXYGEN_FOUND)

    add_custom_target( apidocs 
        COMMAND ${DOXYGEN_EXECUTABLE} lbcrypto-doxy-config
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )

else (DOXYGEN_FOUND)
  message("Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)

include (ExternalProject)

# third party directories
set( THIRDPARTYDIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party )
include_directories( ${THIRDPARTYDIR}/include )

### Handle third-party CEREAL
include_directories( ${THIRDPARTYDIR}/cereal/include )

include_directories( src )
set (SUBMAKEFILES core pke trapdoor abe signature circuit wip)
foreach( dir ${SUBMAKEFILES} )
	include_directories( src/${dir}/lib )
endforeach( dir )

include_directories( third-party/google-test/googletest third-party/google-test/googletest/include )
include_directories( ${CMAKE_CURRENT_BINARY_DIR}/third-party/include )

## for tests
set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)

### handle third-party gmp
set(GMPSRCDIR ${THIRDPARTYDIR}/distros/gmp-6.1.2)
set(GMPLIBDIR ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib)
set(GMPLIBFILE ${GMPLIBDIR}/libgmp${CMAKE_SHARED_LIBRARY_SUFFIX})
set(GMPLIBFILE_STATIC ${GMPLIBDIR}/libgmp${CMAKE_STATIC_LIBRARY_SUFFIX})
set(GMPCONF ${GMPSRCDIR}/config.h)

# unpack gmp distro

add_custom_target(
	gmp_unpack
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf gmp-6.1.2.tar.lz
	COMMAND cd ${GMPSRCDIR} && ./configure --host=${CROSS_TRIPLE} --prefix=${CMAKE_CURRENT_BINARY_DIR}/third-party
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

add_library(gmp_static STATIC IMPORTED GLOBAL)
set_target_properties(gmp_static PROPERTIES IMPORTED_LOCATION ${GMPLIBFILE_STATIC})
add_library(gmp SHARED IMPORTED GLOBAL)
set_target_properties(gmp PROPERTIES IMPORTED_LOCATION ${GMPLIBFILE})

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib DESTINATION .
	FILES_MATCHING PATTERN "libgmp.*" )

### Handle third-party libntl

set(NTLSRCDIR ${THIRDPARTYDIR}/distros/ntl-10.5.0/src)
set(NTLZIPNAME ntl-10.5.0.tar.gz)
set(NTLTARGET all)

set(NTLCONF ${NTLSRCDIR}/../include/NTL/config.h)
set(NTLLIBDIR ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib)
set(NTLLIBFILE ${NTLLIBDIR}/libntl${CMAKE_SHARED_LIBRARY_SUFFIX})
set(NTLLIBFILE_STATIC ${NTLLIBDIR}/libntl${CMAKE_STATIC_LIBRARY_SUFFIX})

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

add_library(ntl_static STATIC IMPORTED GLOBAL)
set_target_properties(ntl_static PROPERTIES IMPORTED_LOCATION ${NTLLIBFILE_STATIC})
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
set_target_properties(tcmalloc PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libtcmalloc_minimal.so)

set(THIRDPARTYLIBS PUBLIC ntl PUBLIC gmp)
set(THIRDPARTYSTATICLIBS PUBLIC ntl_static PUBLIC gmp_static)

### NEED TO ADD THIS LINE IF tcmalloc IS BEING USED
### set(THIRDPARTYLIBS PUBLIC ntl PUBLIC gmp PUBLIC tcmalloc)
###

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/include DESTINATION .)

add_custom_target(third-party ALL DEPENDS ${GMPLIBFILE} ${NTLLIBFILE})

### add each of the subdirs of src
add_subdirectory(src/core)
add_subdirectory(src/pke)
add_subdirectory(src/trapdoor)
add_subdirectory(src/abe)
add_subdirectory(src/signature)
add_subdirectory(src/wip)
## FIXME ## add_subdirectory(src/circuit)

### build the google test handlers
add_subdirectory(third-party/google-test EXCLUDE_FROM_ALL)

### build the google benchmark handlers (just the parts we need)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Enable testing of the benchmark library." FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Enable installation of benchmark. (Projects embedding benchmark may want to turn this OFF.)" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Enable building the unit tests which depend on gtest" FORCE)
add_subdirectory(third-party/google-benchmark EXCLUDE_FROM_ALL)

add_subdirectory(benchmark)
