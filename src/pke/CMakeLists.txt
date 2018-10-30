file (GLOB PKE_SRC_FILES lib/*-impl.cpp)

set (PKELIBS PALISADEpke PALISADEcore ${GMPlib} ${NTLlib} ${OpenMP_CXX_FLAGS})

add_library (PALISADEpke SHARED ${PKE_SRC_FILES} )
add_library (PALISADEpke_static STATIC ${PKE_SRC_FILES} )
target_link_libraries (${PKELIBS})

file (GLOB PKE_TEST_SRC_FILES unittest/*.cpp)
add_executable (pke_tests ${PKE_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( pke_tests ${PKELIBS} )

file (GLOB PKE_DEMO_SRC_FILES demo/*.cpp)
foreach (app ${PKE_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${PKELIBS} )
endforeach()
