file (GLOB PKE_SRC_FILES CONFIGURE_DEPENDS lib/*-impl.cpp)

add_library (pkeobj OBJECT ${PKE_SRC_FILES})
add_dependencies(pkeobj PALISADEcore)
set_property(TARGET pkeobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEpke SHARED $<TARGET_OBJECTS:pkeobj>)
add_library (PALISADEpke_static STATIC $<TARGET_OBJECTS:pkeobj>)

target_include_directories (PALISADEpke PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (PKELIBS PUBLIC PALISADEpke PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEpke PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})
target_link_libraries (PALISADEpke_static PUBLIC PALISADEcore PUBLIC gmp_static PUBLIC ntl_static ${OpenMP_CXX_FLAGS})

file (GLOB PKE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (pke_tests ${PKE_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( pke_tests ${PKELIBS} )

file (GLOB PKE_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${PKE_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${PKELIBS} )
endforeach()
