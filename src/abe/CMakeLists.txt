file (GLOB ABE_SRC_FILES CONFIGURE_DEPENDS lib/*-impl.cpp)

add_library(abeobj OBJECT ${ABE_SRC_FILES})
add_dependencies(abeobj PALISADEpke)
set_property(TARGET abeobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEabe SHARED $<TARGET_OBJECTS:abeobj>)
add_library (PALISADEabe_static STATIC $<TARGET_OBJECTS:abeobj>)

target_include_directories (PALISADEabe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (ABELIBS PUBLIC PALISADEabe PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEabe PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})
target_link_libraries (PALISADEabe_static PUBLIC PALISADEcore_static PUBLIC gmp_static PUBLIC ntl_static ${OpenMP_CXX_FLAGS})

file (GLOB ABE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (abe_tests ${ABE_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( abe_tests ${ABELIBS} )

file (GLOB ABE_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${ABE_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${ABELIBS} )
endforeach()
