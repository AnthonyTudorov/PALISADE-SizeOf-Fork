find_package (FLEX REQUIRED)
find_package (BISON REQUIRED)

flex_target(lexer lib/scan.l "${CMAKE_CURRENT_BINARY_DIR}/scan.cpp")
bison_target(parser lib/parse.y "${CMAKE_CURRENT_BINARY_DIR}/parse.cpp")
add_flex_bison_dependency(lexer parser)

file (GLOB CIRCUIT_SRC_FILES CONFIGURE_DEPENDS lib/*.cpp)

add_library(circobj OBJECT
	${CIRCUIT_SRC_FILES}
	${FLEX_lexer_OUTPUTS}
	${BISON_parser_OUTPUTS}
)
target_include_directories( circobj PUBLIC ${CMAKE_CURRENT_BINARY_DIR} )
add_dependencies(circobj PALISADEpke)
set_property(TARGET circobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEcircuit SHARED $<TARGET_OBJECTS:circobj>)
install(TARGETS PALISADEcircuit DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEcircuit_static STATIC $<TARGET_OBJECTS:circobj>)
	install(TARGETS PALISADEcircuit_static DESTINATION lib)
endif()

set (CIRCUITLIBS PUBLIC PALISADEcircuit PUBLIC PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEcircuit PUBLIC PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEcircuit_static PUBLIC PALISADEpke_static PUBLIC PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

file (GLOB CIRCUIT_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (circuit_tests ${CIRCUIT_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( circuit_tests ${CIRCUITLIBS} )

set (CIRCUITAPPS "")
file (GLOB CIRCUIT_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${CIRCUIT_DEMO_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	set( CIRCUITAPPS ${CIRCUITAPPS} ${exe} )
	target_link_libraries ( ${exe} ${CIRCUITLIBS} )
endforeach()

add_custom_target( allcircuit )
add_dependencies( allcircuit PALISADEcircuit ${CIRCUITAPPS} circuit_tests )
