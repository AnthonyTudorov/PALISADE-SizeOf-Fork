file (GLOB WIP_SRC_FILES CONFIGURE_DEPENDS lib/*.cpp lib/*/*.cpp)

add_library(wipobj OBJECT ${WIP_SRC_FILES})
add_dependencies(wipobj PALISADEpke)
set_property(TARGET wipobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEwip SHARED $<TARGET_OBJECTS:wipobj>)
install(TARGETS PALISADEwip DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEwip_static STATIC $<TARGET_OBJECTS:wipobj>)
	install(TARGETS PALISADEwip_static DESTINATION lib)
endif()

target_include_directories (PALISADEwip PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (WIPLIBS PUBLIC PALISADEwip PUBLIC PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEwip PUBLIC PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEwip_static PUBLIC PALISADEpke_static PUBLIC PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

file (GLOB WIP_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (wip_tests ${WIP_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( wip_tests ${WIPLIBS} )

set (WIPAPPS "")
file (GLOB WIP_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${WIP_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	set (WIPAPPS ${WIPAPPS} ${APP})
	target_link_libraries ( ${APP} ${WIPLIBS} )
        install ( TARGETS ${APP} DESTINATION demo/wip )
endforeach()

install(TARGETS wip_tests DESTINATION unittest)

### NOTE there's no WIP demos...
### add_custom_target( allwipdemos )
### add_dependencies( allwipdemos "${WIPAPPS}" )

add_custom_target( allwip )
add_dependencies( allwip PALISADEwip wip_tests )

add_custom_command( OUTPUT wipinfocmd COMMAND echo Builds PALISADEwip )
add_custom_target( wipinfo DEPENDS wipinfocmd )

add_custom_command( OUTPUT runwiptests COMMAND ${CMAKE_CURRENT_BINARY_DIR}/wip_tests )
add_custom_target( testwip DEPENDS runwiptests )

