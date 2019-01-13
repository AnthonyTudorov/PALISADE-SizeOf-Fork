file (GLOB_RECURSE CORE_SRC_FILES CONFIGURE_DEPENDS lib/*.cpp)

add_library(coreobj OBJECT ${CORE_SRC_FILES})
add_dependencies(coreobj third-party)
set_property(TARGET coreobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEcore SHARED $<TARGET_OBJECTS:coreobj>)
add_library (PALISADEcore_static STATIC $<TARGET_OBJECTS:coreobj>)

target_include_directories (PALISADEcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (CORELIBS PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})
target_link_libraries (PALISADEcore_static PUBLIC gmp_static PUBLIC ntl_static ${OpenMP_CXX_FLAGS})

file (GLOB CORE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
set (CORE_TEST_SRC_FILES ${CORE_TEST_SRC_FILES})
add_executable( core_tests ${CORE_TEST_SRC_FILES} ${UNITTESTMAIN} )
target_link_libraries ( core_tests ${CORELIBS} )

file (GLOB CORE_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${CORE_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${CORELIBS} )
endforeach()
