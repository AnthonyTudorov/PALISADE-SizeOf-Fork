file (GLOB BACKEND_SRC_FILES lib/math/*/*.cpp)
file (GLOB MATH_SRC_FILES lib/math/*.cpp)
file (GLOB LATTICE_SRC_FILES lib/lattice/*.cpp)
file (GLOB ENCODING_SRC_FILES lib/encoding/*.cpp)
file (GLOB UTILS_SRC_FILES lib/utils/*.cpp lib/utils/*/*.cpp)

set(coresrc
	${BACKEND_SRC_FILES}
	${MATH_SRC_FILES}
	${LATTICE_SRC_FILES}
	${ENCODING_SRC_FILES}
	${UTILS_SRC_FILES} )

add_library(coreobj OBJECT ${coresrc})
add_dependencies(coreobj third-party)
set_property(TARGET coreobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEcore SHARED $<TARGET_OBJECTS:coreobj>)
add_library (PALISADEcore_static STATIC $<TARGET_OBJECTS:coreobj>)

target_include_directories (PALISADEcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (CORELIBS PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})
target_link_libraries (PALISADEcore_static PUBLIC gmp_static PUBLIC ntl_static ${OpenMP_CXX_FLAGS})

file (GLOB CORE_TEST_SRC_FILES unittest/*.cpp)
add_executable( core_tests ${CORE_TEST_SRC_FILES} ${UNITTESTMAIN} )
target_link_libraries ( core_tests ${CORELIBS} )

file (GLOB CORE_DEMO_SRC_FILES demo/*.cpp)
foreach (app ${CORE_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_link_libraries ( ${APP} ${CORELIBS} )
endforeach()
