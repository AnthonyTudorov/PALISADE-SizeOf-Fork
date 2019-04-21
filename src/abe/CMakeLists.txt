file (GLOB ABE_SRC_FILES CONFIGURE_DEPENDS lib/*-impl.cpp)

set(ABE_VERSION_MAJOR 1)
set(ABE_VERSION_MINOR 1)
set(ABE_VERSION_PATCH 6)
set(ABE_VERSION ${ABE_VERSION_MAJOR}.${ABE_VERSION_MINOR}.${ABE_VERSION_PATCH})

add_library(abeobj OBJECT ${ABE_SRC_FILES})
add_dependencies(abeobj PALISADEpke)
set_property(TARGET abeobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEabe SHARED $<TARGET_OBJECTS:abeobj>)
set_property(TARGET PALISADEabe PROPERTY VERSION ${ABE_VERSION})
set_property(TARGET PALISADEabe PROPERTY SOVERSION ${ABE_VERSION_MAJOR})
install(TARGETS PALISADEabe DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEabe_static STATIC $<TARGET_OBJECTS:abeobj>)
	install(TARGETS PALISADEabe_static DESTINATION lib)
endif()

target_include_directories (PALISADEabe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (ABELIBS PUBLIC PALISADEabe PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEabe PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEabe_static PUBLIC PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

file (GLOB ABE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (abe_tests ${ABE_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( abe_tests ${ABELIBS} )

set (ABEAPPS "")
file (GLOB ABE_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${ABE_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	set( ABEAPPS ${ABEAPPS} ${APP} )
	target_link_libraries ( ${APP} ${ABELIBS} )
        install ( TARGETS ${APP} DESTINATION demo/abe )
endforeach()

install(TARGETS abe_tests DESTINATION unittest)

add_custom_target( allabedemos )
add_dependencies( allabedemos ${ABEAPPS} )

add_custom_target( allabe )
add_dependencies( allabe PALISADEabe allabedemos abe_tests )

add_custom_command( OUTPUT abeinfocmd COMMAND echo Builds PALISADEabe and these apps: ${ABEAPPS} )
add_custom_target( abeinfo DEPENDS abeinfocmd )

add_custom_command( OUTPUT runabetests COMMAND ${CMAKE_CURRENT_BINARY_DIR}/abe_tests )
add_custom_target( testabe DEPENDS runabetests )

