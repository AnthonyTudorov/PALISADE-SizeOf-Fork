file (GLOB WIP_SRC_FILES lib/*.cpp lib/*/*.cpp)

add_library(wipobj OBJECT ${WIP_SRC_FILES})
add_dependencies(wipobj PALISADEpke)
set_property(TARGET wipobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEwip SHARED $<TARGET_OBJECTS:wipobj>)
add_library (PALISADEwip_static STATIC $<TARGET_OBJECTS:wipobj>)

target_include_directories (PALISADEwip PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (WIPLIBS PUBLIC PALISADEwip PUBLIC PALISADEpke PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEwip PUBLIC PALISADEpke PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})
target_link_libraries (PALISADEwip_static PUBLIC PALISADEpke_static PUBLIC PALISADEcore_static PUBLIC gmp_static PUBLIC ntl_static ${OpenMP_CXX_FLAGS})

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
