find_package (Flex REQUIRED)
find_package (Bison REQUIRED)

file (GLOB CIRCUIT_SRC_FILES CONFIGURE_DEPENDS lib/*.cpp lib/*.l lib/*.y)

add_library(circobj OBJECT ${CIRCUIT_SRC_FILES})
add_dependencies(circobj PALISADEpke)
set_property(TARGET circobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEcircuit SHARED $<TARGET_OBJECTS:circobj>)
install(TARGETS PALISADEcircuit DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEcircuit_static STATIC $<TARGET_OBJECTS:circobj>)
	install(TARGETS PALISADEcircuit_static DESTINATION lib)
endif()

set (CIRCUITLIBS PUBLIC PALISADEcircuit PUBLIC PALISADEpke PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEcircuit PUBLIC PALISADEpke PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEcircuit_static PUBLIC PALISADEpke_static PUBLIC PALISADEcore_static PUBLIC gmp_static PUBLIC ntl_static ${OpenMP_CXX_FLAGS})
endif()

file (GLOB CIRCUIT_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (circuit_tests ${CIRCUIT_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( circuit_tests ${CIRCUITLIBS} )

set (CIRCUITAPPS "")
file (GLOB CIRCUIT_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${CIRCUIT_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	set (CIRCUITAPPS ${CIRCUITAPPS} ${APP})
	target_link_libraries ( ${APP} ${CIRCUITLIBS} )
        install ( TARGETS ${APP} DESTINATION demo/circuit )
endforeach()

install(TARGETS circuit_tests DESTINATION unittest)

add_custom_target( allcircuit )
add_dependencies( allcircuit PALISADEcircuit ${CIRCUITAPPS} circuit_tests )
