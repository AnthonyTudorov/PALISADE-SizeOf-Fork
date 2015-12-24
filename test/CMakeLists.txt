cmake_minimum_required(VERSION 3.3)
project(test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    include/gtest/gtest-all.cc
    include/gtest/gtest.h
    src/Main_TestAll.cpp
    src/UnitTestBinInt.cpp
    src/UnitTestBinMat.cpp
    src/UnitTestBinVect.cpp
    src/UnitTestDistrGen.cpp
    src/UnitTestNbTheory.cpp)

add_executable(test ${SOURCE_FILES})