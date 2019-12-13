file (GLOB TRAPDOOR_SRC_FILES CONFIGURE_DEPENDS lib/*-impl.cpp lib/*/*-impl.cpp)

include_directories( ../core/include )
include_directories( ../pke/include )
include_directories( include )
include_directories( lib )

set(TRAPDOOR_VERSION_MAJOR ${PALISADE_VERSION_MAJOR})
set(TRAPDOOR_VERSION_MINOR ${PALISADE_VERSION_MINOR})
set(TRAPDOOR_VERSION_PATCH ${PALISADE_VERSION_PATCH})
set(TRAPDOOR_VERSION ${TRAPDOOR_VERSION_MAJOR}.${TRAPDOOR_VERSION_MINOR}.${TRAPDOOR_VERSION_PATCH})

add_library(trapdoorobj OBJECT ${TRAPDOOR_SRC_FILES})
add_dependencies(trapdoorobj PALISADEpke)
set_property(TARGET trapdoorobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEtrapdoor SHARED $<TARGET_OBJECTS:trapdoorobj>)
set_property(TARGET PALISADEtrapdoor PROPERTY VERSION ${TRAPDOOR_VERSION})
set_property(TARGET PALISADEtrapdoor PROPERTY SOVERSION ${TRAPDOOR_VERSION_MAJOR})
set_property(TARGET PALISADEtrapdoor PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
install(TARGETS PALISADEtrapdoor DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEtrapdoor_static STATIC $<TARGET_OBJECTS:trapdoorobj>)
	set_property(TARGET PALISADEtrapdoor_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS PALISADEtrapdoor_static DESTINATION lib)
endif()

install(DIRECTORY include/ DESTINATION include/trapdoor)

target_include_directories (PALISADEtrapdoor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (TRAPDOORLIBS PUBLIC PALISADEtrapdoor PUBLIC PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEtrapdoor PUBLIC PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEtrapdoor_static PUBLIC PALISADEpke_static PUBLIC PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

file (GLOB TRAPDOOR_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (trapdoor_tests ${TRAPDOOR_TEST_SRC_FILES} ${UNITTESTMAIN})
set_property(TARGET trapdoor_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
target_link_libraries ( trapdoor_tests ${TRAPDOORLIBS} )

set (TRAPDOORAPPS "")
file (GLOB TRAPDOOR_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${TRAPDOOR_DEMO_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/demo/trapdoor)
	set( TRAPDOORAPPS ${TRAPDOORAPPS} ${exe} )
	target_link_libraries ( ${exe} ${TRAPDOORLIBS} )
endforeach()

add_custom_target( alltrapdoordemos )
add_dependencies( alltrapdoordemos ${TRAPDOORAPPS} )

add_custom_target( alltrapdoor )
add_dependencies( alltrapdoor PALISADEtrapdoor alltrapdoordemos trapdoor_tests )

add_custom_command( OUTPUT trapdoorinfocmd COMMAND echo Builds PALISADEtrapdoor and these apps: ${TRAPDOORAPPS} )
add_custom_target( trapdoorinfo DEPENDS trapdoorinfocmd )

add_custom_command( OUTPUT runtrapdoortests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/trapdoor_tests )
add_custom_target( testtrapdoor DEPENDS trapdoor_tests runtrapdoortests )
