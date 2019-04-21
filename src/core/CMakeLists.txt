file (GLOB_RECURSE CORE_SRC_FILES CONFIGURE_DEPENDS lib/*.cpp)

set(CORE_VERSION_MAJOR 1)
set(CORE_VERSION_MINOR 1)
set(CORE_VERSION_PATCH 6)
set(CORE_VERSION ${CORE_VERSION_MAJOR}.${CORE_VERSION_MINOR}.${CORE_VERSION_PATCH})

add_library(coreobj OBJECT ${CORE_SRC_FILES})
add_dependencies(coreobj third-party)
set_property(TARGET coreobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEcore SHARED $<TARGET_OBJECTS:coreobj>)
set_property(TARGET PALISADEcore PROPERTY VERSION ${CORE_VERSION})
set_property(TARGET PALISADEcore PROPERTY SOVERSION ${CORE_VERSION_MAJOR})
install(TARGETS PALISADEcore DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEcore_static STATIC $<TARGET_OBJECTS:coreobj>)
	install(TARGETS PALISADEcore_static DESTINATION lib)
endif()

target_include_directories (PALISADEcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (CORELIBS PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

file (GLOB CORE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
set (CORE_TEST_SRC_FILES ${CORE_TEST_SRC_FILES})
add_executable( core_tests ${CORE_TEST_SRC_FILES} ${UNITTESTMAIN} )
target_link_libraries ( core_tests ${CORELIBS} )

set( COREAPPS "" )
file (GLOB CORE_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${CORE_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable ( ${APP} ${app} )
	set( COREAPPS ${COREAPPS} ${APP} )
	target_link_libraries ( ${APP} ${CORELIBS} )
	install ( TARGETS ${APP} DESTINATION demo/core )
endforeach()

install(TARGETS core_tests DESTINATION unittest)

add_custom_target( allcoredemos )
add_dependencies( allcoredemos ${COREAPPS} )

add_custom_target( allcore )
add_dependencies( allcore PALISADEcore allcoredemos core_tests )

add_custom_command( OUTPUT coreinfocmd COMMAND echo Builds PALISADEcore and these apps: ${COREAPPS} )
add_custom_target( coreinfo DEPENDS coreinfocmd )

add_custom_command( OUTPUT runcoretests COMMAND ${CMAKE_CURRENT_BINARY_DIR}/core_tests )
add_custom_target( testcore DEPENDS runcoretests )
