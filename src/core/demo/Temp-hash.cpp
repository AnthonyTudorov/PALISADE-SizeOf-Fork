/*
 * Temp-hash.cpp
 *
 *  Created on: Jul 25, 2017
 *      Author: gwryan
 */

#include <iostream>
#include <iomanip>
#include <string>
using namespace std;

#include "utils/hashutil.h"
using namespace lbcrypto;

int main(int argc, char *argv[])
{
	if( argc != 2 ) {
		cout << "Usage is " << argv[0] << " string-to-hash" << endl;
		return 0;
	}

	cout << std::hex << endl;

	string demo(argv[1]);

	vector<int64_t> digest;
	HashUtil::Hash(demo,SHA_256,digest);
	string sha = HashUtil::HashString(demo);

	cout << demo << std::hex << endl;
	for( size_t ii=0; ii<32; ii++ ) {
		cout << std::setfill('0') << std::setw(2) << (int) digest[ii];
	}
	cout << endl << sha << std::dec << endl;

	return 0;
}
