file (GLOB SIG_SRC_FILES lib/*-impl.cpp)

add_library(sigobj OBJECT ${SIG_SRC_FILES})
add_dependencies(sigobj PALISADEpke)
set_property(TARGET sigobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEsignature SHARED $<TARGET_OBJECTS:sigobj>)
add_library (PALISADEsignature_static STATIC $<TARGET_OBJECTS:sigobj>)

target_include_directories (PALISADEsignature PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (SIGLIBS PUBLIC PALISADEsignature PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEsignature PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})
target_link_libraries (PALISADEsignature_static PUBLIC PALISADEcore_static PUBLIC gmp_static PUBLIC ntl_static ${OpenMP_CXX_FLAGS})

file (GLOB SIG_TEST_SRC_FILES unittest/*.cpp)
add_executable (sig_tests ${SIG_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( sig_tests ${SIGLIBS} )

file (GLOB SIG_DEMO_SRC_FILES demo/*.cpp)
foreach (app ${SIG_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${SIGLIBS} )
endforeach()
