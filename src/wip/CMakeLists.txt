file (GLOB WIP_SRC_FILES CONFIGURE_DEPENDS lib/*.cpp lib/*/*.cpp)

set(WIP_VERSION_MAJOR 1)
set(WIP_VERSION_MINOR 1)
set(WIP_VERSION_PATCH 6)
set(WIP_VERSION ${WIP_VERSION_MAJOR}.${WIP_VERSION_MINOR}.${WIP_VERSION_PATCH})

add_library(wipobj OBJECT ${WIP_SRC_FILES})
add_dependencies(wipobj PALISADEpke)
set_property(TARGET wipobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEwip SHARED $<TARGET_OBJECTS:wipobj>)
set_property(TARGET PALISADEwip PROPERTY VERSION ${WIP_VERSION})
set_property(TARGET PALISADEwip PROPERTY SOVERSION ${WIP_VERSION_MAJOR})
set_property(TARGET PALISADEwip PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
install(TARGETS PALISADEwip DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEwip_static STATIC $<TARGET_OBJECTS:wipobj>)
	set_property(TARGET PALISADEwip_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
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
set_property(TARGET wip_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
target_link_libraries ( wip_tests ${WIPLIBS} )

set (WIPAPPS "")
file (GLOB WIP_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${WIP_DEMO_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/demo/wip)
	set( WIPAPPS ${WIPAPPS} ${exe} )
	target_link_libraries ( ${exe} ${WIPLIBS} )
endforeach()

### NOTE there's no WIP demos...
### add_custom_target( allwipdemos )
### add_dependencies( allwipdemos "${WIPAPPS}" )

add_custom_target( allwip )
add_dependencies( allwip PALISADEwip wip_tests )

add_custom_command( OUTPUT wipinfocmd COMMAND echo Builds PALISADEwip )
add_custom_target( wipinfo DEPENDS wipinfocmd )

add_custom_command( OUTPUT runwiptests COMMAND ${CMAKE_BINARY_DIR}/unittest/wip_tests )
add_custom_target( testwip DEPENDS wip_tests runwiptests )
