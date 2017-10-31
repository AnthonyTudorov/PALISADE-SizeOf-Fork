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

int main()
{
	cout << std::hex << endl;

	string empty = "";
	string demo = "The quick brown fox jumps over the lazy dog";

	vector<uint8_t> digest;
	HashUtil::Hash(empty,SHA_256,digest);
	string sha = HashUtil::HashString(empty);

	cout << "Empty string" << std::hex << endl;
	for( size_t ii=0; ii<32; ii++ ) {
		cout << std::setfill('0') << std::setw(2) << (int)digest[ii];
	}
	cout << endl << sha << std::dec << endl;

	HashUtil::Hash(demo,SHA_256,digest);
	sha = HashUtil::HashString(demo);

	cout << "The quick brown fox jumps over the lazy dog" << std::hex << endl;
	for( size_t ii=0; ii<32; ii++ ) {
		cout << std::setfill('0') << std::setw(2) << (int) digest[ii];
	}
	cout << endl << sha << std::dec << endl;

}
