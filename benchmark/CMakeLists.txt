set( REGEX_FLAG -DHAVE_STD_REGEX ) #note does not work for g++ <version 4.9

if ( APPLE )
	set( WARNING_FLAG "" )
else()
	set( WARNING_FLAG -Wno-unused-but-set-variable )
endif()

set (BMLIBS PUBLIC PALISADEpke PUBLIC PALISADEcore PUBLIC gmp PUBLIC ntl ${OpenMP_CXX_FLAGS})

file (GLOB BMARK_SRC_FILES CONFIGURE_DEPENDS src/*.cpp)
foreach (app ${BMARK_SRC_FILES})
	string ( REGEX REPLACE "/\.*/" "" FN ${app})
	string ( REPLACE ".cpp" "" APP ${FN})
	add_executable( ${APP} ${app} )
	target_include_directories( ${APP} PUBLIC ../third-party/google-benchmark/include )
	set_target_properties( ${APP} PROPERTIES COMPILE_FLAGS
		"${REGEX_FLAG} -DHAVE_STEADY_CLOCK -DNDEBUG ${WARNING_FLAG} -Wno-unused-variable" )
	target_link_libraries ( ${APP} ${BMLIBS} )
        install ( TARGETS ${APP} DESTINATION benchmark )
endforeach()


