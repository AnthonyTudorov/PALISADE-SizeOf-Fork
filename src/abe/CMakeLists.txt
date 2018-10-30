file (GLOB ABE_SRC_FILES lib/*-impl.cpp)

set (ABELIBS PALISADEabe PALISADEcore ${GMPlib} ${NTLlib} ${OpenMP_CXX_FLAGS})

add_library (PALISADEabe SHARED ${ABE_SRC_FILES} )
add_library (PALISADEabe_static STATIC ${ABE_SRC_FILES} )
target_link_libraries (${ABELIBS})

file (GLOB ABE_TEST_SRC_FILES unittest/*.cpp)
add_executable (abe_tests ${ABE_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( abe_tests ${ABELIBS} )

file (GLOB ABE_DEMO_SRC_FILES demo/*.cpp)
foreach (app ${ABE_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${ABELIBS} )
endforeach()
