/*
 * Temp-hash.cpp
 *
 *  Created on: Jul 25, 2017
 *      Author: gwryan
 */

#include <iostream>
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

	cout << "Empty string" << endl;
	for( size_t ii=0; ii<32; ii++ ) {
		cout << (int)shabytes[ii];
	}
	cout << endl << sha << endl;

	BytePlaintextEncoding ptxt2(demo);
	BytePlaintextEncoding shabytes2 = HashUtil::Hash(ptxt2,SHA_256);
	sha = HashUtil::HashString(demo);

	cout << "The quick brown fox jumps over the lazy dog" << endl;
	for( size_t ii=0; ii<32; ii++ ) {
		cout << (int) shabytes2[ii];
	}
	cout << endl << sha << endl;

}
