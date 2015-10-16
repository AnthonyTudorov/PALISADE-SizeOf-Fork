CXX=g++
FLAGS=-g -L../lib -I../include
LIBS=-static -ljson

SOURCE_FILES=saveparams.cpp lwecrypt.cpp
BIN_FILE=../bin/NTRU-PRE

all:
	$(CXX) $(FLAGS) -o $(BIN_FILE) $(SOURCE_FILES) $(LIBS)
