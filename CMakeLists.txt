cmake_minimum_required (VERSION 3.1)

project (PALISADE CXX)

#if(APPLE)
#	set(CMAKE_CXX_COMPILER /opt/local/bin/clang++)
#	set(OPENMP_LIBRARIES "/usr/local/lib/libomp")
#	set(OPENMP_INCLUDES "/opt/local/include/libopenmp")
#	#CPPSTD := -std=c++11 -stdlib=libc++ -fPIC
#	#CC := /opt/local/bin/clang++ $(CPPSTD)
#endif()

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
find_library(GMPlib NAMES gmp PATHS ${THIRDPARTYLIBDIR})
find_library(NTLlib NAMES ntl PATHS ${THIRDPARTYLIBDIR})

include_directories( third-party/google-test/googletest third-party/google-test/googletest/include )
include_directories( ${THIRDPARTYDIR}/include ${THIRDPARTYDIR}/rapidjson/include )
include_directories( /opt/local/include/libomp )

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
  find_package(OpenMP REQUIRED)
endif()

if (OPENMP_FOUND)
    include_directories("${OPENMP_INCLUDES}")
    link_directories("${OPENMP_LIBRARIES}")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    # set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

### Library directories
add_subdirectory(src/core)
add_subdirectory(src/pke)
#add_subdirectory(src/trapdoor)
#add_subdirectory(src/abe)
#add_subdirectory(src/signature)
#add_subdirectory(src/wip)
#add_subdirectory(src/circuit)
