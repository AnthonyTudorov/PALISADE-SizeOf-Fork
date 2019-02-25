file (GLOB TRAPDOOR_SRC_FILES CONFIGURE_DEPENDS lib/*-impl.cpp lib/*/*-impl.cpp)

add_library(trapdoorobj OBJECT ${TRAPDOOR_SRC_FILES})
add_dependencies(trapdoorobj PALISADEpke)
set_property(TARGET trapdoorobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEtrapdoor SHARED $<TARGET_OBJECTS:trapdoorobj>)
install(TARGETS PALISADEtrapdoor DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEtrapdoor_static STATIC $<TARGET_OBJECTS:trapdoorobj>)
	install(TARGETS PALISADEtrapdoor_static DESTINATION lib)
endif()

target_include_directories (PALISADEtrapdoor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (TRAPDOORLIBS PUBLIC PALISADEtrapdoor PUBLIC PALISADEpke PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEtrapdoor PUBLIC PALISADEpke PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEtrapdoor_static PUBLIC PALISADEpke_static PUBLIC PALISADEcore_static PUBLIC gmp_static PUBLIC ntl_static ${OpenMP_CXX_FLAGS})
endif()

file (GLOB TRAPDOOR_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (trapdoor_tests ${TRAPDOOR_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( trapdoor_tests ${TRAPDOORLIBS} )

set (TRAPDOORAPPS "")
file (GLOB TRAPDOOR_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${TRAPDOOR_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	set (TRAPDOORAPPS ${TRAPDOORAPPS} ${APP})
	target_link_libraries ( ${APP} ${TRAPDOORLIBS} )
        install ( TARGETS ${APP} DESTINATION demo/trapdoor )
endforeach()

install(TARGETS trapdoor_tests DESTINATION unittest)

add_custom_target( alltrapdoor )
add_dependencies( alltrapdoor PALISADEtrapdoor ${TRAPDOORAPPS} trapdoor_tests )
