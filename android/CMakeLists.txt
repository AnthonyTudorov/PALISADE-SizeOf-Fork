include(FindJNI)

add_library (paljniobj OBJECT jni/PALISADE/PALISADEjni.cpp)
set_property(TARGET paljniobj PROPERTY POSITION_INDEPENDENT_CODE 1)
target_include_directories (paljniobj PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${JNI_INCLUDE_DIRS})

add_library (PALISADEjni SHARED $<TARGET_OBJECTS:paljniobj>)
set_property(TARGET PALISADEpke PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
install(TARGETS PALISADEjni DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEjni_static STATIC $<TARGET_OBJECTS:paljniobj>)
	set_property(TARGET PALISADEjni_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS PALISADEjni_static DESTINATION lib)
endif()

set (JNILIBS PUBLIC PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEjni ${JNILIBS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEjni_static PUBLIC PALISADEcore_static PUBLIC PALISADEpke_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()
