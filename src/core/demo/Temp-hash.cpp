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

	BytePlaintextEncoding ptxt(empty);
	BytePlaintextEncoding shabytes = HashUtil::Hash(ptxt,SHA_256);
	string sha = HashUtil::HashString(empty);

	cout << "Empty string" << std::hex << endl;
	for( size_t ii=0; ii<32; ii++ ) {
		cout << std::setfill('0') << std::setw(2) << (int)shabytes[ii];
	}
	cout << endl << sha << std::dec << endl;

	BytePlaintextEncoding ptxt2(demo);
	BytePlaintextEncoding shabytes2 = HashUtil::Hash(ptxt2,SHA_256);
	sha = HashUtil::HashString(demo);

	cout << "The quick brown fox jumps over the lazy dog" << std::hex << endl;
	for( size_t ii=0; ii<32; ii++ ) {
		cout << std::setfill('0') << std::setw(2) << (int) shabytes2[ii];
	}
	cout << endl << sha << std::dec << endl;

}
