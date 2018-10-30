file (GLOB WIP_SRC_FILES lib/*.cpp lib/*/*.cpp)

set (WIPLIBS PALISADEwip PALISADEpke PALISADEcore ${GMPlib} ${NTLlib} ${OpenMP_CXX_FLAGS})

add_library (PALISADEwip SHARED ${WIP_SRC_FILES} )
add_library (PALISADEwip_static STATIC ${WIP_SRC_FILES} )
target_link_libraries (${WIPLIBS})

file (GLOB WIP_TEST_SRC_FILES unittest/*.cpp)
add_executable (wiptests ${WIP_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( wiptests ${WIPLIBS} )

file (GLOB WIP_DEMO_SRC_FILES demo/*.cpp)
foreach (app ${WIP_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${WIPLIBS} )
endforeach()
