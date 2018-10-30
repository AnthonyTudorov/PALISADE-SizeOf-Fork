file (GLOB TRAPDOOR_SRC_FILES lib/*-impl.cpp lib/*/*-impl.cpp)

set (TRAPDOORLIBS PALISADEtrapdoor PALISADEpke PALISADEcore ${GMPlib} ${NTLlib} ${OpenMP_CXX_FLAGS})

add_library (PALISADEtrapdoor SHARED ${TRAPDOOR_SRC_FILES} )
add_library (PALISADEtrapdoor_static STATIC ${TRAPDOOR_SRC_FILES} )
target_link_libraries (${TRAPDOORLIBS})

file (GLOB TRAPDOOR_TEST_SRC_FILES unittest/*.cpp)
add_executable (trapdoortests ${TRAPDOOR_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( trapdoortests ${TRAPDOORLIBS} )

file (GLOB TRAPDOOR_DEMO_SRC_FILES demo/*.cpp)
foreach (app ${TRAPDOOR_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${TRAPDOORLIBS} )
endforeach()
