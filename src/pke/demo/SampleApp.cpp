/*
 * SampleApp.cpp
 *
 *  Created on: Oct 5, 2016
 *      Author: gerardryan
 */

#include <iostream>
#include <string>
#include <vector>
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::vector;

#include "palisade.h"

#include "cryptocontexthelper.h"

using namespace lbcrypto;

void demoCrypto(bool doJson);

void
usage()
{
	cout << "--help this message" << endl;
	cout << "--null put the scheme into null mode" << endl;
	cout << "--print prints out all the schemes" << endl;
	cout << "--prompt prompts user for scheme name" << endl;
	cout << "SCHEME select the scheme name (--print SCHEME prints it out)" << endl;
}

int
main( int argc, char *argv[] )
{
	string parmSetName = "";
	bool doPrint = false;
	bool doPrompt = false;

	for( int i=1; i<argc; i++ ) {
		string arg(argv[i]);

		if( arg == "--help" ) {
			usage();
			return 0;
		}
		else if( arg == "--print" ) {
			doPrint = true;
		}
		else if( arg[0] == '-' ) {
			usage();
			return 0;
		}
		else
			parmSetName = arg;
	}

	if( doPrint ) {
		if( parmSetName.length() == 0 )
			CryptoContextHelper<ILVector2n>::printAllParmSets(cout);
		else
			CryptoContextHelper<ILVector2n>::printParmSet(cout, parmSetName);

		return 0;
	}

	while( doPrompt ) {
		cout << "Choose parameter set: ";
		CryptoContextHelper<ILVector2n>::printAllParmSetNames(cout);

		string input;
		std::cin >> input;

		if( knownParameterSet(input) ) {
			parmSetName = input;
			break;
		}

		cout << input << " is not a known parameter set name" << endl;
	}

	if( parmSetName.length() == 0 )
		parmSetName = "Null"; // default

	CryptoContext<ILVector2n> cc = CryptoContextHelper<ILVector2n>::getNewContext(parmSetName);

	return 0;
}


