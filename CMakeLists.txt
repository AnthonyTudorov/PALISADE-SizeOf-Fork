cmake_minimum_required (VERSION 3.1)

project (PALISADE CXX)
find_package (Git REQUIRED)
#find_package (Flex REQUIRED)
#find_package (Bison REQUIRED)

include (ExternalProject)

# handle rapidjson as an include-only submodule
#find_path(RAPIDJSON_INCLUDE_DIR third-party/rapidjson/include)
#message(${RAPIDJSON_INCLUDE_DIR})

find_path(RAPIDJSON_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/rapidjson/include PATHS ${CMAKE_CURRENT_SOURCE_DIR})
message(${RAPIDJSON_INCLUDE_DIR})

#find_path(RAPIDJSON_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/rapidjson/include )
#message(${RAPIDJSON_INCLUDE_DIR})

if((NOT RAPIDJSON_INCLUDE_DIR) OR (NOT EXISTS ${RAPIDJSON_INCLUDE_DIR}))
    # we couldn't find the header files for FOO or they don't exist
    message("Unable to find rapidjson")

    # we have a submodule setup for rapidjson
    # now we need to clone this submodule
    execute_process(COMMAND git submodule update --init -- third-party/rapidjson
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    # set RAPIDJSON_INCLUDE_DIR properly
    set(RAPIDJSON_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/rapidjson/include
        CACHE PATH "rapidjson include directory")

    # also install it?
    #install(DIRECTORY ${RAPIDJSON_INCLUDE_DIR}/foo DESTINATION ${some_dest})

    # need to export target as well
    #install(TARGETS foo EXPORT my_export_set DESTINATION ${some_dest})
else()
    # set RAPIDJSON_INCLUDE_DIR properly
    set(RAPIDJSON_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/rapidjson/include
        CACHE PATH "rapidjson include directory")
endif()

message("xxx")
message(${RAPIDJSON_INCLUDE_DIR})
# for convenience setup a target
add_library(rapidjson INTERFACE)
include_directories( ${RAPIDJSON_INCLUDE_DIR} )
		       ##$<INSTALL_INTERFACE:${some_dest}>)

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
set( THIRDPARTYLIBDIR ${THIRDPARTYDIR}/lib )

# find the third party libraries
link_directories( ${THIRDPARTYLIBDIR} )
find_library(GMPlib NAMES gmp PATHS ${THIRDPARTYLIBDIR})
find_library(NTLlib NAMES ntl PATHS ${THIRDPARTYLIBDIR})

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

### Library directories
add_subdirectory(src/core)
add_subdirectory(src/pke)
add_subdirectory(src/trapdoor)
add_subdirectory(src/wip)
add_subdirectory(src/circuit)

#add_subdirectory(src/abe)
#add_subdirectory(src/signature)
