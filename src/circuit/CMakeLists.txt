file (GLOB CIRCUIT_SRC_FILES lib/*.cpp lib/*.l lib/*.y)

set (CIRCUITLIBS PALISADEcircuit PALISADEpke PALISADEcore ${GMPlib} ${NTLlib} ${OpenMP_CXX_FLAGS})

add_library (PALISADEcircuit SHARED ${CIRCUIT_SRC_FILES} )
add_library (PALISADEcircuit_static STATIC ${CIRCUIT_SRC_FILES} )
target_link_libraries (${CIRCUITLIBS})

file (GLOB CIRCUIT_TEST_SRC_FILES unittest/*.cpp)
add_executable (circuit_tests ${CIRCUIT_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( circuit_tests ${CIRCUITLIBS} )

file (GLOB CIRCUIT_DEMO_SRC_FILES demo/*.cpp)
foreach (app ${CIRCUIT_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${CIRCUITLIBS} )
endforeach()
