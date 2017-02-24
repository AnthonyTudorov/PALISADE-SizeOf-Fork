#include <utility>
#include <iostream>

#define _USE_MATH_DEFINES
#include "math/backend.h"
#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;

int main( int argc, char *argv[] ) {
	BigBinaryInteger mod, rootUnity;
	int shifts[] = { 30, 60, 100, 300, 500 };

	for( int o=8; o<1024; o *= 2 ) {
		cout << o << ":" << endl;
		for( int s = 0; s < sizeof(shifts)/sizeof(shifts[0]); s++ ) {
			mod = FindPrimeModulus(o, shifts[s]);
			rootUnity = RootOfUnity(o, mod);

			cout << o << ": " << shifts[s] << ": " << mod << ": " << rootUnity << endl;
		}
	}

	return 0;
}
