cmake_minimum_required (VERSION 3.4)

project (PALISADE C CXX)
find_package (Git REQUIRED)
#find_package (Flex REQUIRED)
#find_package (Bison REQUIRED)

include (ExternalProject)

### Handle third-party RAPIDJSON
find_file(RAPIDJSONINC include PATHS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/rapidjson NO_DEFAULT_PATH)

if((NOT RAPIDJSONINC) OR (NOT EXISTS ${RAPIDJSONINC}))
    message("Unable to find rapidjson")

    # we have a submodule setup for rapidjson
    # so we need to clone this submodule
    execute_process(COMMAND git submodule update --init -- third-party/rapidjson
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    # set RAPIDJSON_INCLUDE_DIR properly
    set(RAPIDJSONINC ${CMAKE_CURRENT_SOURCE_DIR}/third-party/rapidjson/include
        CACHE PATH "rapidjson include directory")

    # also install it?
    #install(DIRECTORY ${RAPIDJSON_INCLUDE_DIR}/foo DESTINATION ${some_dest})

    # need to export target as well
    #install(TARGETS foo EXPORT my_export_set DESTINATION ${some_dest})
endif()

# for convenience setup a target
add_library(rapidjson INTERFACE)
include_directories( ${RAPIDJSONINC} )

if(APPLE)
	set(CMAKE_CXX_COMPILER /opt/local/bin/clang++)
#	set(OPENMP_LIBRARIES "/usr/local/lib/libomp")
#	set(OPENMP_INCLUDES "/opt/local/include/libopenmp")
#	#CPPSTD := -std=c++11 -stdlib=libc++ -fPIC
#	#CC := /opt/local/bin/clang++ $(CPPSTD)
endif()

set (CMAKE_CXX_STANDARD 11)

include_directories( src )
set (SUBMAKEFILES core pke trapdoor abe signature circuit wip)
foreach( dir ${SUBMAKEFILES} )
	include_directories( src/${dir}/lib )
endforeach( dir )

# third party directories
set( THIRDPARTYDIR third-party )
include_directories( ${THIRDPARTYDIR}/include )

set( THIRDPARTYLIBDIR ${THIRDPARTYDIR}/lib )

# find the third party libraries
link_directories( ${THIRDPARTYLIBDIR} )

include_directories( third-party/google-test/googletest third-party/google-test/googletest/include )
include_directories( ${THIRDPARTYDIR}/include ) #${THIRDPARTYDIR}/rapidjson/include )

find_package(OpenMP REQUIRED)

if (OPENMP_FOUND)
    #include_directories("${OPENMP_INCLUDES}")
    #link_directories("${OPENMP_LIBRARIES}")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

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

## for tests
set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)

### handle third-party gmp
set(GMPDIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/distros/gmp-6.1.2)

# unpack distro
add_custom_command(
	OUTPUT ${GMPDIR}
	COMMAND tar xf gmp-6.1.2.tar.lz
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/third-party/distros
)

add_custom_target(GMPlib ALL
    DEPENDS GMPlib-config
    COMMAND make
    WORKING_DIRECTORY ${GMPDIR}
)

add_custom_target(GMPlib-config
    DEPENDS ${GMPDIR}
    COMMAND ./configure
    WORKING_DIRECTORY ${GMPDIR}
    BYPRODUCTS config.h
)

### Handle third-party libntl
set(NTLDIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/distros/ntl-10.5.0)

# unpack distro
add_custom_command(
    OUTPUT ${NTLDIR}
    COMMAND tar xf ntl-10.5.0.tar.gz
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/third-party/distros
)

add_custom_target(NTLlib ALL
    DEPENDS NTLlib-config
    COMMAND make
    WORKING_DIRECTORY ${NTLDIR}
)

add_custom_target(NTLlib-config
    DEPENDS ${NTLDIR}
    COMMAND ./configure
    WORKING_DIRECTORY ${NTLDIR}
    BYPRODUCTS config.h
)

add_subdirectory(src/core)
##add_subdirectory(src/pke)
##add_subdirectory(src/trapdoor)
##add_subdirectory(src/wip)
##add_subdirectory(src/circuit)

#add_subdirectory(src/abe)
#add_subdirectory(src/signature)
