file (GLOB SIG_SRC_FILES CONFIGURE_DEPENDS lib/*-impl.cpp)

set(SIG_VERSION_MAJOR 1)
set(SIG_VERSION_MINOR 1)
set(SIG_VERSION_PATCH 6)
set(SIG_VERSION ${SIG_VERSION_MAJOR}.${SIG_VERSION_MINOR}.${SIG_VERSION_PATCH})

add_library(sigobj OBJECT ${SIG_SRC_FILES})
add_dependencies(sigobj PALISADEpke)
set_property(TARGET sigobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEsignature SHARED $<TARGET_OBJECTS:sigobj>)
set_property(TARGET PALISADEsignature PROPERTY VERSION ${SIG_VERSION})
set_property(TARGET PALISADEsignature PROPERTY SOVERSION ${SIG_VERSION_MAJOR})
install(TARGETS PALISADEsignature DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEsignature_static STATIC $<TARGET_OBJECTS:sigobj>)
	install(TARGETS PALISADEsignature_static DESTINATION lib)
endif()

target_include_directories (PALISADEsignature PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (SIGLIBS PUBLIC PALISADEsignature PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEsignature PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEsignature_static PUBLIC PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

file (GLOB SIG_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (signature_tests ${SIG_TEST_SRC_FILES} ${UNITTESTMAIN})
target_link_libraries ( signature_tests ${SIGLIBS} )

set (SIGAPPS "")
file (GLOB SIG_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${SIG_DEMO_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	set (SIGAPPS ${SIGAPPS} ${APP})
	target_link_libraries ( ${APP} ${SIGLIBS} )
        install ( TARGETS ${APP} DESTINATION demo/signature )
endforeach()

install(TARGETS signature_tests DESTINATION unittest)

add_custom_target( allsignaturedemos )
add_dependencies( allsignaturedemos ${SIGAPPS} )

add_custom_target( allsignature )
add_dependencies( allsignature PALISADEsignature allsignaturedemos signature_tests )

add_custom_command( OUTPUT signatureinfocmd COMMAND echo Builds PALISADEsignature and these apps: ${SIGAPPS} )
add_custom_target( signatureinfo DEPENDS signatureinfocmd )

add_custom_command( OUTPUT runsignaturetests COMMAND ${CMAKE_CURRENT_BINARY_DIR}/signature_tests )
add_custom_target( testsignature DEPENDS runsignaturetests )

