/*
 * palcircuit.cpp
 *
 *  Created on: Apr 7, 2017
 *      Author: gerardryan
 */

#include "parsedriver.h"

int
main(int argc, char *argv[])
{
	bool verbose = false;
	for( int i=1; i<argc; i++ ) {
		if( string(argv[i]) == "-v" ) {
			verbose = true;
			continue;
		}

		pdriver driver(verbose);

		auto res = driver.parse(argv[i]);
		std::cout << "parse result is " << res << std::endl;

		driver.graph.DisplayGraph();
	}

	return 0;
}

