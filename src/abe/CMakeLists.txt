file (GLOB ABE_SRC_FILES lib/*-impl.cpp)
file (GLOB ABE_TEST_FILES unittest/*.cpp)

add_library (PALISADEabe SHARED ${ABE_SRC_FILES} )
add_library (PALISADEabe_static STATIC ${ABE_SRC_FILES} )

add_executable (abe_tests ${ABE_TEST_FILES} ${UNITTESTMAIN})
