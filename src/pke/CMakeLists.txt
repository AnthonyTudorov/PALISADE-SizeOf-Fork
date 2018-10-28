file (GLOB PKE_SRC_FILES lib/*-impl.cpp)

add_library (PALISADEpke SHARED ${PKE_SRC_FILES} )
add_library (PALISADEpke_static STATIC ${PKE_SRC_FILES} )

file (GLOB PKE_TEST_SRC_FILES unittest/*.cpp)
add_executable (pke_tests ${PKE_TEST_SRC_FILES})
