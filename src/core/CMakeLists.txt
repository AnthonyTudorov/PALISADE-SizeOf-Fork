file (GLOB BACKEND_SRC_FILES lib/math/*/*.cpp)
file (GLOB MATH_SRC_FILES lib/math/*.cpp)
file (GLOB LATTICE_SRC_FILES lib/lattice/*.cpp)
file (GLOB ENCODING_SRC_FILES lib/encoding/*.cpp)
file (GLOB UTILS_SRC_FILES lib/utils/*.cpp lib/utils/*/*.cpp)

set (CORELIBS PALISADEcore ${GMPlib} ${NTLlib} ${OpenMP_CXX_FLAGS})

add_library (PALISADEcore SHARED
	${BACKEND_SRC_FILES}
	${MATH_SRC_FILES}
	${LATTICE_SRC_FILES}
	${ENCODING_SRC_FILES}
	${UTILS_SRC_FILES} )
target_link_libraries (${CORELIBS})

add_library (PALISADEcore_static STATIC
	${BACKEND_SRC_FILES}
	${MATH_SRC_FILES}
	${LATTICE_SRC_FILES}
	${ENCODING_SRC_FILES}
	${UTILS_SRC_FILES} )

file (GLOB CORE_TEST_SRC_FILES unittest/*.cpp)
add_executable( core_tests ${CORE_TEST_SRC_FILES} ${UNITTESTMAIN} )
target_link_libraries ( core_tests ${CORELIBS} )
