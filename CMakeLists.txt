cmake_minimum_required (VERSION 3.4)

set(TAR "tar")
if(APPLE)
	set(TAR "gnutar")
endif()

if(APPLE)
	set(CMAKE_C_COMPILER /opt/local/bin/clang)
	set(CMAKE_CXX_COMPILER /opt/local/bin/clang++)
	set(OPENMP_LIBRARIES "/opt/local/lib/openmpi-clang38/openmpi")
	set(OPENMP_INCLUDES "/opt/local/include/openmpi-clang38")
endif()

project (PALISADE C CXX)

set (CMAKE_CXX_STANDARD 11)
if(APPLE)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

set(COMPILEFLAGS "-g -Wall -Werror -O3")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILEFLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMPILEFLAGS}")

OPTION (USE_OpenMP "Use OpenMP to enamble <omp.h>" ON)

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

include (ExternalProject)

# third party directories
set( THIRDPARTYDIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party )
include_directories( ${THIRDPARTYDIR}/include )

### Handle third-party RAPIDJSON
set(RAPIDJSONINC ${THIRDPARTYDIR}/rapidjson/include )

execute_process(
	COMMAND git submodule foreach git submodule update --init
	COMMAND git submodule foreach git pull origin master
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

include_directories( ${RAPIDJSONINC} )

include_directories( src )
set (SUBMAKEFILES core pke trapdoor abe signature circuit wip)
foreach( dir ${SUBMAKEFILES} )
	include_directories( src/${dir}/lib )
endforeach( dir )

set( THIRDPARTYLIBDIR ${THIRDPARTYDIR}/lib )

# find the third party libraries
link_directories( ${THIRDPARTYLIBDIR} )

include_directories( third-party/google-test/googletest third-party/google-test/googletest/include )
include_directories( ${CMAKE_CURRENT_BINARY_DIR}/third-party/include )

## for tests
set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)

### handle third-party gmp
set(GMPSRCDIR ${THIRDPARTYDIR}/distros/gmp-6.1.2)
set(GMPLIBFILE ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libgmp${CMAKE_STATIC_LIBRARY_SUFFIX})
set(GMPCONF ${GMPSRCDIR}/config.h)

# unpack distro
if( NOT EXISTS "${GMPSRCDIR}" )
	execute_process(
		COMMAND ${TAR} xf gmp-6.1.2.tar.lz
		WORKING_DIRECTORY ${THIRDPARTYDIR}/distros
	)
endif()

add_custom_command(
	OUTPUT ${GMPCONF}
	COMMAND ./configure --host=${CROSS_TRIPLE} --prefix=${CMAKE_CURRENT_BINARY_DIR}/third-party
	WORKING_DIRECTORY ${GMPSRCDIR}
)

add_custom_command(
	OUTPUT ${GMPLIBFILE}
	DEPENDS ${GMPCONF}
	COMMAND echo ${GMPLIBFILE}
	COMMAND make 
	COMMAND make install
	WORKING_DIRECTORY ${GMPSRCDIR}
)

add_library(gmp_static STATIC IMPORTED GLOBAL)
set_target_properties(gmp_static PROPERTIES IMPORTED_LOCATION ${GMPLIBFILE})
add_library(gmp SHARED IMPORTED GLOBAL)
set_target_properties(gmp PROPERTIES 
	IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libgmp${CMAKE_SHARED_LIBRARY_SUFFIX})


### Handle third-party libntl
### NOTE NTL doesn't (easily) cross compile; we use a hand-tuned Android version
### there's likely a better way to do this

if(CMAKE_SYSTEM_NAME MATCHES "Android")
	set(NTLSRCDIR ${THIRDPARTYDIR}/distros/cross-ntl-10.5.0/src)
	set(NTLZIPNAME cross-ntl-10.5.0.tar.gz)
	set(NTLTARGET ntl.a)

else()
	set(NTLSRCDIR ${THIRDPARTYDIR}/distros/ntl-10.5.0/src)
	set(NTLZIPNAME ntl-10.5.0.tar.gz)
	set(NTLTARGET all)
endif()
set(NTLCONF ${NTLSRCDIR}/../include/NTL/config.h)
set(NTLLIBFILE ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libntl${CMAKE_STATIC_LIBRARY_SUFFIX})

# unpack distro
if( NOT EXISTS "${NTLSRCDIR}" )
	execute_process(
		COMMAND ${TAR} xf ${NTLZIPNAME}
		WORKING_DIRECTORY ${THIRDPARTYDIR}/distros
	)
endif()

add_custom_command(
    OUTPUT ${NTLCONF}
    COMMAND ./configure2 ${NTLCROSS} PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off

    WORKING_DIRECTORY ${NTLSRCDIR}
)

add_custom_command(
	OUTPUT ${NTLLIBFILE}
	DEPENDS ${NTLCONF} ${GMPLIBFILE}
	COMMAND make ${NTLTARGET}
	COMMAND make install
	WORKING_DIRECTORY ${NTLSRCDIR}
)

add_library(ntl_static STATIC IMPORTED GLOBAL)
set_target_properties(ntl_static PROPERTIES IMPORTED_LOCATION ${NTLLIBFILE})
add_library(ntl SHARED IMPORTED GLOBAL)
set_target_properties(ntl PROPERTIES
	IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libntl${CMAKE_SHARED_LIBRARY_SUFFIX})


add_custom_target(third-party ALL DEPENDS ${RAPIDJSONINC} ${GMPLIBFILE} ${NTLLIBFILE})

add_subdirectory(src/core)
add_subdirectory(src/pke)
add_subdirectory(src/trapdoor)
add_subdirectory(src/abe)
add_subdirectory(src/signature)
add_subdirectory(src/wip)

file (GLOB ALLTESTOBJ CONFIGURE_DEPENDS src/core/CMakeFiles/core_tests.dir/unittest/*.o)
add_executable( all_tests
	${ALLTESTOBJ}
	${ABE_TEST_SRC_FILES}
	${PKE_TEST_SRC_FILES}
	${SIG_TEST_SRC_FILES}
	${TRAPDOOR_TEST_SRC_FILES}
	${WIP_TEST_SRC_FILES}
	${UNITTESTMAIN}
)
target_link_libraries( all_tests PALISADEcore PALISADEpke PALISADEtrapdoor PALISADEabe PALISADEsignature PALISADEwip ntl gmp )
## add_subdirectory(src/circuit)

